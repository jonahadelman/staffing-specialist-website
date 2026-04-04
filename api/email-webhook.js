// api/email-webhook.js — Vercel Edge Function
// Receives Resend webhook events (opened, clicked, replied, bounced, complained).
// Register URL at: Resend → Webhooks → Add endpoint
//
// SECURITY:
//   - RESEND_WEBHOOK_SECRET is REQUIRED — missing env var = 503
//   - Svix signature verified using HMAC-SHA256
//   - Svix timestamp checked: rejects events older than 5 minutes (replay attack prevention)
//   - candidateId validated before use in Supabase URL
//   - Always returns 200 to Resend (prevents retry storms)

export const config = { runtime: 'edge' };

const SAFE_ID_RE        = /^[a-zA-Z0-9_\-]{1,128}$/;
const MAX_TIMESTAMP_AGE = 5 * 60 * 1000; // 5 minutes in ms

// ── RETRY HELPER ─────────────────────────────────────────────
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

const ok = new Response(JSON.stringify({ received: true }), {
  status: 200, headers: { 'Content-Type': 'application/json' },
});

// ── HANDLER ──────────────────────────────────────────────────
export default async function handler(req) {
  if (req.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }

  const SUPABASE_URL   = process.env.SUPABASE_URL;
  const SUPABASE_KEY   = process.env.SUPABASE_KEY || process.env.SUPABASE_SERVICE_KEY;
  const WEBHOOK_SECRET = process.env.RESEND_WEBHOOK_SECRET;

  // ── 1. WEBHOOK SECRET — hard required ────────────────────────
  if (!WEBHOOK_SECRET) {
    // Env var not configured — reject all rather than accept unverified webhooks
    console.error('[webhook] RESEND_WEBHOOK_SECRET not set — rejecting request');
    return new Response(JSON.stringify({ error: 'Webhook not configured' }), {
      status: 503, headers: { 'Content-Type': 'application/json' },
    });
  }

  // ── 2. READ BODY ONCE (needed for signature) ─────────────────
  let bodyText;
  try { bodyText = await req.text(); } catch(e) {
    return new Response('Failed to read request body', { status: 400 });
  }
  if (!bodyText || bodyText.length > 64 * 1024) {
    return new Response('Request body too large or empty', { status: 413 });
  }

  // ── 3. SVIX SIGNATURE VERIFICATION ───────────────────────────
  const svixId        = req.headers.get('svix-id')        || '';
  const svixTimestamp = req.headers.get('svix-timestamp')  || '';
  const svixSig       = req.headers.get('svix-signature')  || '';

  if (!svixId || !svixTimestamp || !svixSig) {
    return new Response('Missing svix signature headers', { status: 401 });
  }

  // ── 4. TIMESTAMP CHECK — prevent replay attacks ───────────────
  // svix-timestamp is seconds since epoch
  const eventTimeMs = parseInt(svixTimestamp, 10) * 1000;
  const ageMs       = Date.now() - eventTimeMs;
  if (isNaN(eventTimeMs) || ageMs > MAX_TIMESTAMP_AGE || ageMs < -MAX_TIMESTAMP_AGE) {
    console.warn('[webhook] Rejected stale/future timestamp:', svixTimestamp, 'age:', ageMs, 'ms');
    return new Response('Request timestamp too old or in the future', { status: 401 });
  }

  // ── 5. HMAC VERIFICATION ─────────────────────────────────────
  try {
    const encoder      = new TextEncoder();
    // Strip whsec_ prefix if present
    const secretBytes  = Uint8Array.from(atob(WEBHOOK_SECRET.replace(/^whsec_/, '')), c => c.charCodeAt(0));
    const cryptoKey    = await crypto.subtle.importKey(
      'raw', secretBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    );
    const signedContent = encoder.encode(`${svixId}.${svixTimestamp}.${bodyText}`);

    // svix-signature may contain multiple v1,<base64> entries separated by spaces
    const sigs = svixSig.split(' ')
      .map(s => s.replace(/^v1,/, ''))
      .filter(Boolean);

    if (!sigs.length) {
      return new Response('No valid signature entries', { status: 401 });
    }

    // Check each signature — any valid one passes (svix key rotation)
    let verified = false;
    for (const sig of sigs) {
      try {
        const sigBytes = Uint8Array.from(atob(sig), c => c.charCodeAt(0));
        const ok       = await crypto.subtle.verify('HMAC', cryptoKey, sigBytes, signedContent);
        if (ok) { verified = true; break; }
      } catch(e) { /* try next */ }
    }

    if (!verified) {
      console.warn('[webhook] Signature verification failed for svix-id:', svixId);
      return new Response('Invalid webhook signature', { status: 401 });
    }
  } catch(e) {
    console.error('[webhook] Signature check threw:', e.message);
    return new Response('Webhook verification error', { status: 401 });
  }

  // ── 6. PARSE EVENT ────────────────────────────────────────────
  let event;
  try { event = JSON.parse(bodyText); } catch(e) {
    return new Response('Invalid JSON', { status: 400 });
  }

  // Always 200 from here — Resend won't retry a 200
  if (!SUPABASE_URL || !SUPABASE_KEY) return ok.clone();

  const eventType = String(event.type || '');
  const HANDLED   = new Set([
    'email.opened', 'email.clicked', 'email.replied',
    'email.bounced', 'email.complained',
  ]);
  if (!HANDLED.has(eventType)) return ok.clone();

  const data = event.data || {};

  // ── 7. EXTRACT + VALIDATE CANDIDATE ID ───────────────────────
  const tagEntry    = Array.isArray(data.tags) ? data.tags.find(t => t.name === 'tracking_id') : null;
  const trackingId  = String((tagEntry && tagEntry.value) || '').trim();

  if (!trackingId || !SAFE_ID_RE.test(trackingId)) return ok.clone();

  const dashIdx     = trackingId.lastIndexOf('-');
  const candidateId = dashIdx > 0 ? trackingId.slice(0, dashIdx) : trackingId;

  if (!candidateId || !SAFE_ID_RE.test(candidateId)) return ok.clone();

  const sbHeaders = {
    'apikey'       : SUPABASE_KEY,
    'Authorization': `Bearer ${SUPABASE_KEY}`,
    'Content-Type' : 'application/json',
    'Prefer'       : 'return=minimal',
  };

  // ── 8. PERSIST — fire and forget ─────────────────────────────
  (async () => {
    try {
      await sbWrite(`${SUPABASE_URL}/rest/v1/activity`, {
        method : 'POST',
        headers: sbHeaders,
        body   : JSON.stringify({
          candidate_id: candidateId,
          text        : `Resend: ${eventType}`,
          tracking_id : trackingId,
          created_at  : new Date().toISOString(),
        }),
      });

      const getRes = await sbWrite(
        `${SUPABASE_URL}/rest/v1/candidates?id=eq.${encodeURIComponent(candidateId)}&select=id,data`,
        { headers: sbHeaders }
      );
      if (!getRes.ok) return;
      const rows = await getRes.json();
      if (!Array.isArray(rows) || !rows[0]) return;

      const cdata = rows[0].data || {};
      if (!cdata.activity) cdata.activity = [];

      if (eventType === 'email.opened') {
        if (cdata.opened) return; // de-dupe
        cdata.opened          = true;
        cdata.openedAt        = Date.now();
        cdata.engagementBoost = Math.min((cdata.engagementBoost || 0) + 10, 40);
        cdata.activity.push({ ts: Date.now(), text: 'Email opened (webhook confirmed)' });

      } else if (eventType === 'email.replied') {
        cdata.responded         = true;
        cdata.respondedAt       = Date.now();
        cdata.engagementBoost   = Math.min((cdata.engagementBoost || 0) + 30, 40);
        cdata.forcedTemperature = 'hot';
        cdata.lastContacted     = Date.now();
        cdata.activity.push({ ts: Date.now(), text: 'Candidate replied to outreach ↩' });

      } else if (eventType === 'email.clicked') {
        cdata.engagementBoost = Math.min((cdata.engagementBoost || 0) + 5, 40);
        cdata.activity.push({ ts: Date.now(), text: 'Email link clicked' });

      } else if (eventType === 'email.bounced') {
        cdata.emailBounced = true;
        cdata.activity.push({ ts: Date.now(), text: '⚠ Email bounced — verify address' });

      } else if (eventType === 'email.complained') {
        cdata.emailComplained = true;
        cdata.activity.push({ ts: Date.now(), text: '🚫 Spam complaint received' });
      }

      await sbWrite(
        `${SUPABASE_URL}/rest/v1/candidates?id=eq.${encodeURIComponent(candidateId)}`,
        { method: 'PATCH', headers: sbHeaders, body: JSON.stringify({ data: cdata }) }
      );
    } catch(e) {
      console.error('[webhook] Supabase write failed:', e.message);
    }
  })();

  return ok.clone();
}
