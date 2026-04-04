// api/track-open.js — Vercel Edge Function
// Open-tracking pixel. Returns 1×1 GIF instantly, logs to Supabase async.
//
// SECURITY:
//   - No auth required (pixel URLs are embedded in emails sent to recipients)
//   - Rate limited per IP: 60 requests/min (bot/scraper protection)
//   - candidateId validated: alphanumeric+hyphen, max 128 chars
//   - De-duplication in Supabase write (cdata.opened check)
//   - Never exposes candidate data in response

export const config = { runtime: 'edge' };

const PIXEL_GIF      = 'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';
const PIXEL_RESPONSE = new Response(
  Uint8Array.from(atob(PIXEL_GIF), c => c.charCodeAt(0)),
  {
    status: 200,
    headers: {
      'Content-Type'  : 'image/gif',
      'Cache-Control' : 'no-store, no-cache, must-revalidate, max-age=0',
      'Pragma'        : 'no-cache',
      'Content-Length': '43',
    },
  }
);

// ── RATE LIMITER ──────────────────────────────────────────────
const _buckets = new Map();
function checkRate(ip, limit = 60, windowMs = 60_000) {
  const now = Date.now();
  let b = _buckets.get(ip);
  if (!b || now > b.reset) b = { count: 0, reset: now + windowMs };
  b.count++;
  _buckets.set(ip, b);
  return b.count <= limit;
}

// ── SUPABASE WRITE WITH ONE RETRY ─────────────────────────────
async function sbWrite(url, opts, attempt = 1) {
  try {
    const r = await fetch(url, opts);
    if (!r.ok && attempt < 2) {
      await new Promise(res => setTimeout(res, 400));
      return sbWrite(url, opts, 2);
    }
    return r;
  } catch(e) {
    if (attempt < 2) {
      await new Promise(res => setTimeout(res, 400));
      return sbWrite(url, opts, 2);
    }
    throw e;
  }
}

// ── INPUT VALIDATION ─────────────────────────────────────────
// candidateId comes from trackingId which we generated — format: <uid>-<timestamp>
// uid() produces alphanumeric, timestamp is numeric. Safe chars only.
const SAFE_ID_RE = /^[a-zA-Z0-9_\-]{1,128}$/;

export default async function handler(req) {
  // Always respond immediately with pixel — never block
  const respond = () => PIXEL_RESPONSE.clone();

  // Rate limit by IP — protects Supabase from pixel-spam floods
  const ip = (req.headers.get('x-forwarded-for') || '').split(',')[0].trim() || 'unknown';
  if (!checkRate(ip)) return respond(); // silently drop excess, still return pixel

  const url    = new URL(req.url);
  const rawId  = (url.searchParams.get('id') || '').trim();
  const userId = (url.searchParams.get('uid') || '').trim() || null;

  // Validate input — reject obviously malformed IDs before hitting Supabase
  if (!rawId || !SAFE_ID_RE.test(rawId)) return respond();
  if (userId && !SAFE_ID_RE.test(userId)) return respond();

  // candidateId is everything before the last dash (strips timestamp suffix)
  const dashIdx     = rawId.lastIndexOf('-');
  const candidateId = dashIdx > 0 ? rawId.slice(0, dashIdx) : rawId;

  if (!candidateId || !SAFE_ID_RE.test(candidateId)) return respond();

  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_KEY = process.env.SUPABASE_KEY || process.env.SUPABASE_SERVICE_KEY;

  if (!SUPABASE_URL || !SUPABASE_KEY) return respond();

  const sbHeaders = {
    'apikey'       : SUPABASE_KEY,
    'Authorization': `Bearer ${SUPABASE_KEY}`,
    'Content-Type' : 'application/json',
    'Prefer'       : 'return=minimal',
  };

  // Fire async — response already returned to the email client
  (async () => {
    try {
      // 1. Log activity
      await sbWrite(`${SUPABASE_URL}/rest/v1/activity`, {
        method : 'POST',
        headers: sbHeaders,
        body   : JSON.stringify({
          candidate_id: candidateId,
          user_id     : userId,
          text        : 'Email opened',
          tracking_id : rawId,
          created_at  : new Date().toISOString(),
        }),
      });

      // 2. Read candidate
      const getRes = await sbWrite(
        `${SUPABASE_URL}/rest/v1/candidates?id=eq.${encodeURIComponent(candidateId)}&select=id,data`,
        { headers: sbHeaders }
      );
      if (!getRes.ok) return;
      const rows = await getRes.json();
      if (!Array.isArray(rows) || !rows[0]) return;

      const cdata = rows[0].data || {};
      if (cdata.opened) return; // already recorded — de-dupe

      // 3. Update candidate
      cdata.opened          = true;
      cdata.openedAt        = Date.now();
      cdata.engagementBoost = Math.min((cdata.engagementBoost || 0) + 10, 40); // cap boost
      if (!cdata.activity) cdata.activity = [];
      cdata.activity.push({ ts: Date.now(), text: 'Email opened (tracked)' });

      await sbWrite(
        `${SUPABASE_URL}/rest/v1/candidates?id=eq.${encodeURIComponent(candidateId)}`,
        { method: 'PATCH', headers: sbHeaders, body: JSON.stringify({ data: cdata }) }
      );
    } catch(e) {
      // Silent failure — pixel already sent, never block recipient's email client
      console.error('[track-open]', e.message);
    }
  })();

  return respond();
}
