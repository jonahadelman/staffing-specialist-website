// api/email-webhook.js — Vercel Edge Function
// Receives Resend webhook events. Handles all 5 tracked event types.
// Fix 3: candidate matching uses trackingId ONLY — no email fallback.
// Fix 4: Supabase writes retry once before failing silently.
// Fix 5: handles opened, replied, clicked, bounced, complained.
// Register at: Resend → Webhooks → Add endpoint

export const config = { runtime: 'edge' };

// Fix 4: retry helper
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
    throw e;
  }
}

export default async function handler(req) {
  if (req.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }

  const SUPABASE_URL    = process.env.SUPABASE_URL;
  const SUPABASE_KEY    = process.env.SUPABASE_KEY || process.env.SUPABASE_SERVICE_KEY;
  const WEBHOOK_SECRET  = process.env.RESEND_WEBHOOK_SECRET || '';

  // Verify Resend svix signature
  if (WEBHOOK_SECRET) {
    const svixId        = req.headers.get('svix-id');
    const svixTimestamp = req.headers.get('svix-timestamp');
    const svixSig       = req.headers.get('svix-signature');
    if (!svixId || !svixTimestamp || !svixSig) {
      return new Response('Missing signature headers', { status: 401 });
    }
    try {
      const bodyText     = await req.text();
      const encoder      = new TextEncoder();
      const keyData      = encoder.encode(WEBHOOK_SECRET.replace(/^whsec_/, ''));
      const cryptoKey    = await crypto.subtle.importKey('raw', keyData, { name:'HMAC', hash:'SHA-256' }, false, ['verify']);
      const signedContent = encoder.encode(`${svixId}.${svixTimestamp}.${bodyText}`);
      const sigs         = svixSig.split(' ').map(s => s.replace(/^v1,/, ''));
      const valid        = await Promise.any(sigs.map(async sig => {
        const buf = Uint8Array.from(atob(sig), c => c.charCodeAt(0));
        const ok  = await crypto.subtle.verify('HMAC', cryptoKey, buf, signedContent);
        if (!ok) throw new Error('invalid');
        return true;
      }));
      if (!valid) return new Response('Invalid signature', { status: 401 });
      req = new Request(req.url, { method: req.method, headers: req.headers, body: bodyText });
    } catch(e) {
      return new Response('Webhook verification failed', { status: 401 });
    }
  }

  let event;
  try { event = await req.json(); } catch(e) {
    return new Response('Invalid JSON', { status: 400 });
  }

  // Always 200 after this point — Resend won't retry on 200
  const ok = new Response(JSON.stringify({ received: true }), {
    status: 200, headers: { 'Content-Type': 'application/json' }
  });

  if (!SUPABASE_URL || !SUPABASE_KEY) return ok;

  const eventType = event.type || '';

  // Fix 5: handle all 5 event types
  const HANDLED = new Set(['email.opened','email.clicked','email.replied','email.bounced','email.complained']);
  if (!HANDLED.has(eventType)) return ok;

  const data = event.data || {};

  // Fix 3: use trackingId ONLY for candidate matching — no email fallback
  // Resend stores our tag as data.tags[0].value (tag name = 'tracking_id')
  const tagEntry    = (data.tags || []).find(t => t.name === 'tracking_id');
  const trackingId  = (tagEntry && tagEntry.value) || '';
  const dashIdx     = trackingId.lastIndexOf('-');
  const candidateId = dashIdx > 0 ? trackingId.slice(0, dashIdx) : trackingId;

  if (!candidateId) return ok; // can't correlate without trackingId

  const headers = {
    'apikey'       : SUPABASE_KEY,
    'Authorization': `Bearer ${SUPABASE_KEY}`,
    'Content-Type' : 'application/json',
    'Prefer'       : 'return=minimal',
  };

  // Fire-and-forget — response already prepared
  (async () => {
    try {
      // Fix 4: Log activity with retry
      await sbWrite(`${SUPABASE_URL}/rest/v1/activity`, {
        method : 'POST',
        headers,
        body: JSON.stringify({
          candidate_id: candidateId,
          text        : `Resend webhook: ${eventType}`,
          tracking_id : trackingId,
          created_at  : new Date().toISOString(),
        }),
      });

      // Fix 4: Read candidate with retry
      const getRes = await sbWrite(
        `${SUPABASE_URL}/rest/v1/candidates?id=eq.${encodeURIComponent(candidateId)}&select=id,data`,
        { headers }
      );
      const rows = await getRes.json();
      if (!rows || !rows[0]) return;

      const cdata = rows[0].data || {};
      if (!cdata.activity) cdata.activity = [];

      // Fix 5: update candidate flags per event type
      if (eventType === 'email.opened') {
        if (!cdata.opened) {
          cdata.opened          = true;
          cdata.openedAt        = Date.now();
          cdata.engagementBoost = (cdata.engagementBoost || 0) + 10;
          cdata.activity.push({ ts: Date.now(), text: 'Email opened (webhook confirmed)' });
        }
      } else if (eventType === 'email.replied') {
        cdata.responded         = true;
        cdata.respondedAt       = Date.now();
        cdata.engagementBoost   = (cdata.engagementBoost || 0) + 30;
        cdata.forcedTemperature = 'hot'; // Fix 6: hot lead boost
        cdata.lastContacted     = Date.now();
        cdata.activity.push({ ts: Date.now(), text: 'Candidate replied to outreach ↩' });
      } else if (eventType === 'email.clicked') {
        cdata.engagementBoost = (cdata.engagementBoost || 0) + 5;
        cdata.activity.push({ ts: Date.now(), text: 'Email link clicked' });
      } else if (eventType === 'email.bounced') {
        cdata.emailBounced = true;
        cdata.activity.push({ ts: Date.now(), text: '⚠ Email bounced — verify address' });
      } else if (eventType === 'email.complained') {
        cdata.emailComplained = true;
        cdata.activity.push({ ts: Date.now(), text: '🚫 Spam complaint received' });
      }

      // Fix 4: Patch with retry
      await sbWrite(
        `${SUPABASE_URL}/rest/v1/candidates?id=eq.${encodeURIComponent(candidateId)}`,
        { method: 'PATCH', headers, body: JSON.stringify({ data: cdata }) }
      );
    } catch(e) {
      console.error('[email-webhook] Failed after retry:', e.message);
      // Never throws — 200 already returned
    }
  })();

  return ok;
}
