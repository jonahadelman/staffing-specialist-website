// api/track-open.js — Vercel Edge Function
// Open-tracking pixel. Returns 1x1 GIF instantly, logs to Supabase async.
// Fix 1: URL is always absolute — configured via VERCEL_URL env var.
// Fix 4: Supabase writes retry once before failing silently.

export const config = { runtime: 'edge' };

const PIXEL_GIF = 'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';

// Fix 4: retry helper — tries once, waits 300ms, tries again, then gives up
async function sbWrite(url, opts, attempt) {
  attempt = attempt || 1;
  try {
    const r = await fetch(url, opts);
    if (!r.ok && attempt < 2) {
      await new Promise(res => setTimeout(res, 300));
      return sbWrite(url, opts, 2);
    }
    return r;
  } catch(e) {
    if (attempt < 2) {
      await new Promise(res => setTimeout(res, 300));
      return sbWrite(url, opts, 2);
    }
    throw e; // fail silently at call site
  }
}

export default async function handler(req) {
  const url     = new URL(req.url);
  const rawId   = url.searchParams.get('id') || '';
  const userId  = url.searchParams.get('uid') || null;

  // Always respond with pixel immediately
  const pixelResponse = () => new Response(
    Buffer.from(PIXEL_GIF, 'base64'),
    { status: 200, headers: {
      'Content-Type'  : 'image/gif',
      'Cache-Control' : 'no-store, no-cache, must-revalidate, max-age=0',
      'Pragma'        : 'no-cache',
    }}
  );

  // Fix 3: derive candidateId from trackingId only — no email fallback
  const dashIdx     = rawId.lastIndexOf('-');
  const candidateId = dashIdx > 0 ? rawId.slice(0, dashIdx) : rawId;

  if (!candidateId) return pixelResponse();

  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_KEY = process.env.SUPABASE_KEY || process.env.SUPABASE_SERVICE_KEY;

  if (!SUPABASE_URL || !SUPABASE_KEY) return pixelResponse();

  const headers = {
    'apikey'       : SUPABASE_KEY,
    'Authorization': `Bearer ${SUPABASE_KEY}`,
    'Content-Type' : 'application/json',
    'Prefer'       : 'return=minimal',
  };

  // Fire async — never block the pixel response
  (async () => {
    try {
      // Fix 4: Log activity with retry
      await sbWrite(`${SUPABASE_URL}/rest/v1/activity`, {
        method : 'POST',
        headers,
        body: JSON.stringify({
          candidate_id: candidateId,
          user_id     : userId,
          text        : 'Email opened',
          tracking_id : rawId,
          created_at  : new Date().toISOString(),
        }),
      });

      // Fix 4: Read + patch candidate with retry
      const getRes = await sbWrite(
        `${SUPABASE_URL}/rest/v1/candidates?id=eq.${encodeURIComponent(candidateId)}&select=id,data`,
        { headers }
      );
      const rows = await getRes.json();
      if (!rows || !rows[0]) return;

      const cdata = rows[0].data || {};
      if (cdata.opened) return; // de-dupe

      cdata.opened          = true;
      cdata.openedAt        = Date.now();
      cdata.engagementBoost = (cdata.engagementBoost || 0) + 10;
      if (!cdata.activity) cdata.activity = [];
      cdata.activity.push({ ts: Date.now(), text: 'Email opened (tracked)' });

      // Fix 4: Patch with retry
      await sbWrite(
        `${SUPABASE_URL}/rest/v1/candidates?id=eq.${encodeURIComponent(candidateId)}`,
        { method: 'PATCH', headers, body: JSON.stringify({ data: cdata }) }
      );
    } catch(e) {
      console.error('[track-open] Supabase failed after retry:', e.message);
      // Never throws — pixel already sent
    }
  })();

  return pixelResponse();
}
