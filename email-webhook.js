// api/email-webhook.js — Vercel Edge Function
// Receives Resend webhook events (email.delivered, email.opened, email.replied etc.)
// Register this URL in: Resend Dashboard → Webhooks → Add endpoint
// Set SUPABASE_URL, SUPABASE_SERVICE_KEY, RESEND_WEBHOOK_SECRET in Vercel env vars.

export const config = { runtime: 'edge' };

export default async function handler(req) {
  if (req.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }

  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;
  const WEBHOOK_SECRET = process.env.RESEND_WEBHOOK_SECRET || '';

  // Verify Resend webhook signature (svix-based)
  // Resend sends: svix-id, svix-timestamp, svix-signature headers
  if (WEBHOOK_SECRET) {
    const svixId        = req.headers.get('svix-id');
    const svixTimestamp = req.headers.get('svix-timestamp');
    const svixSig       = req.headers.get('svix-signature');
    if (!svixId || !svixTimestamp || !svixSig) {
      return new Response('Missing webhook signature headers', { status: 401 });
    }
    // Full HMAC-SHA256 verification
    try {
      const body        = await req.text();
      const encoder     = new TextEncoder();
      const keyData     = encoder.encode(WEBHOOK_SECRET.replace(/^whsec_/, ''));
      const cryptoKey   = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
      const signedContent = encoder.encode(`${svixId}.${svixTimestamp}.${body}`);
      const sigBytes    = svixSig.split(' ').map(s => s.replace(/^v1,/, ''));
      const valid       = await Promise.any(sigBytes.map(async sig => {
        const sigBuf = Uint8Array.from(atob(sig), c => c.charCodeAt(0));
        const ok     = await crypto.subtle.verify('HMAC', cryptoKey, sigBuf, signedContent);
        if (!ok) throw new Error('invalid');
        return true;
      }));
      if (!valid) return new Response('Invalid signature', { status: 401 });
      // Re-parse body since we consumed the stream
      req = new Request(req.url, { method: req.method, headers: req.headers, body });
    } catch(e) {
      return new Response('Webhook verification failed', { status: 401 });
    }
  }

  let event;
  try { event = await req.json(); } catch(e) {
    return new Response('Invalid JSON', { status: 400 });
  }

  if (!SUPABASE_URL || !SUPABASE_KEY) {
    console.warn('[webhook] Supabase env vars not set — event not logged');
    return new Response(JSON.stringify({ received: true }), {
      status: 200, headers: { 'Content-Type': 'application/json' }
    });
  }

  const eventType = event.type || '';
  const data      = event.data || {};

  // Map Resend event types
  // email.sent, email.delivered, email.opened, email.clicked, email.replied,
  // email.bounced, email.complained, email.unsubscribed
  const HANDLED = new Set(['email.opened','email.clicked','email.replied','email.bounced','email.complained']);
  if (!HANDLED.has(eventType)) {
    return new Response(JSON.stringify({ received: true, skipped: true }), {
      status: 200, headers: { 'Content-Type': 'application/json' }
    });
  }

  // Resend embeds the tracking_id we passed as a tag or in custom data
  // We store it as: data.tags[0].value or data.metadata.candidateId
  const trackingId  = (data.tags && data.tags[0] && data.tags[0].value) || '';
  const recipientEmail = data.to?.[0] || data.to || '';
  const dashIdx     = trackingId.lastIndexOf('-');
  const candidateId = dashIdx > 0 ? trackingId.slice(0, dashIdx) : trackingId;

  // Helper: fire Supabase REST
  const sb = async (path, method, body) => {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
      method,
      headers: {
        'apikey'       : SUPABASE_KEY,
        'Authorization': `Bearer ${SUPABASE_KEY}`,
        'Content-Type' : 'application/json',
        'Prefer'       : 'return=minimal',
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    return r;
  };

  try {
    // Find candidate by tracking ID or email
    let candRow = null;
    if (candidateId) {
      const r = await fetch(
        `${SUPABASE_URL}/rest/v1/candidates?id=eq.${encodeURIComponent(candidateId)}&select=id,data`,
        { headers: { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}` } }
      );
      const rows = await r.json();
      candRow = rows && rows[0];
    }
    // Fallback: search by email in data jsonb
    if (!candRow && recipientEmail) {
      const r = await fetch(
        `${SUPABASE_URL}/rest/v1/candidates?data->>email=eq.${encodeURIComponent(recipientEmail)}&select=id,data&limit=1`,
        { headers: { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}` } }
      );
      const rows = await r.json();
      candRow = rows && rows[0];
    }

    // Log activity regardless of whether we found the candidate
    await sb('activity', 'POST', {
      candidate_id: candRow ? candRow.id : (candidateId || null),
      text        : `Resend webhook: ${eventType}`,
      tracking_id : trackingId,
      email       : recipientEmail,
      created_at  : new Date().toISOString(),
    });

    // Update candidate CRM fields
    if (candRow) {
      const cdata = candRow.data || {};
      if (!cdata.activity) cdata.activity = [];

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
        cdata.forcedTemperature = 'hot';  // hot lead boost
        cdata.activity.push({ ts: Date.now(), text: 'Candidate replied to outreach ↩' });
        cdata.lastContacted = Date.now();
      } else if (eventType === 'email.clicked') {
        cdata.engagementBoost = (cdata.engagementBoost || 0) + 5;
        cdata.activity.push({ ts: Date.now(), text: 'Email link clicked' });
      } else if (eventType === 'email.bounced') {
        cdata.emailBounced = true;
        cdata.activity.push({ ts: Date.now(), text: '⚠ Email bounced — check address' });
      } else if (eventType === 'email.complained') {
        cdata.emailComplained = true;
        cdata.activity.push({ ts: Date.now(), text: '⚠ Spam complaint received' });
      }

      await sb(`candidates?id=eq.${encodeURIComponent(candRow.id)}`, 'PATCH', { data: cdata });
    }
  } catch(e) {
    console.error('[webhook] Processing failed:', e.message);
    // Still return 200 so Resend doesn't retry forever
  }

  return new Response(JSON.stringify({ received: true }), {
    status: 200, headers: { 'Content-Type': 'application/json' }
  });
}
