// api/send-email.js — Vercel Edge Function
// Proxies email sends to Resend. Keeps API key server-side only.
//
// REQUIRED Vercel env vars:
//   RESEND_API_KEY      — your Resend key
//   EMAIL_SECRET        — generate once: openssl rand -hex 32
//                         also stored in TalentBase Workspace Settings → Email
//
// The frontend sends: x-tb-secret: <EMAIL_SECRET>
// Any request without the correct secret returns 401.

export const config = { runtime: 'edge' };

const ALLOWED_ORIGINS = [
  'https://www.thestaffingspecialist.com',
  'https://thestaffingspecialist.com',
];

// ── RATE LIMITER — per-IP token bucket ───────────────────────
const _rateBuckets = new Map();
const RATE_LIMIT   = 20;       // emails per window per IP
const RATE_WINDOW  = 60_000;   // 60 seconds

function checkRateLimit(ip) {
  const now = Date.now();
  let b = _rateBuckets.get(ip);
  if (!b || now > b.reset) b = { count: 0, reset: now + RATE_WINDOW };
  b.count++;
  _rateBuckets.set(ip, b);
  return b.count <= RATE_LIMIT;
}

// ── HANDLER ──────────────────────────────────────────────────
export default async function handler(req) {
  const origin = req.headers.get('origin') || '';
  const corsHeaders = {
    'Access-Control-Allow-Origin' : ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0],
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, x-tb-secret',
  };

  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders });
  if (req.method !== 'POST') return new Response(JSON.stringify({ error: 'Method not allowed' }), {
    status: 405, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
  });

  // ── AUTH: shared secret ──────────────────────────────────────
  const EMAIL_SECRET = process.env.EMAIL_SECRET;
  if (EMAIL_SECRET) {
    const provided = req.headers.get('x-tb-secret') || '';
    if (provided !== EMAIL_SECRET) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
  }

  // ── RATE LIMIT ───────────────────────────────────────────────
  const ip = (req.headers.get('x-forwarded-for') || '').split(',')[0].trim() || 'unknown';
  if (!checkRateLimit(ip)) {
    return new Response(JSON.stringify({ error: 'Rate limit exceeded. Try again in a minute.' }), {
      status: 429, headers: { ...corsHeaders, 'Content-Type': 'application/json', 'Retry-After': '60' }
    });
  }

  const RESEND_KEY = process.env.RESEND_API_KEY;
  if (!RESEND_KEY) return new Response(JSON.stringify({ error: 'Email service not configured' }), {
    status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
  });

  let body;
  try { body = await req.json(); } catch(e) {
    return new Response(JSON.stringify({ error: 'Invalid request body' }), {
      status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }

  const { to, subject, html, text, from_name, tags, tracking_id } = body;
  if (!to || !subject || (!html && !text)) {
    return new Response(JSON.stringify({ error: 'Missing required fields: to, subject, html/text' }), {
      status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }

  const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const recipients = Array.isArray(to) ? to : [to];
  if (recipients.length > 50) {
    return new Response(JSON.stringify({ error: 'Recipient count exceeds limit (50 max)' }), {
      status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
  for (const addr of recipients) {
    if (!emailRe.test(addr)) {
      return new Response(JSON.stringify({ error: `Invalid email address: ${addr}` }), {
        status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
  }

  try {
    const resendPayload = {
      from   : `${(from_name || 'Jonah Adelman').slice(0, 100)} <onboarding@resend.dev>`,
      to     : recipients,
      subject: String(subject).slice(0, 500),
      html   : html || `<pre style="font-family:sans-serif">${text}</pre>`,
      text   : text || (html || '').replace(/<[^>]+>/g, '') || '',
    };
    if (tags && Array.isArray(tags) && tags.length) resendPayload.tags = tags.slice(0, 10);
    else if (tracking_id) resendPayload.tags = [{ name: 'tracking_id', value: String(tracking_id).slice(0, 256) }];

    const resendRes = await fetch('https://api.resend.com/emails', {
      method : 'POST',
      headers: { 'Authorization': `Bearer ${RESEND_KEY}`, 'Content-Type': 'application/json' },
      body   : JSON.stringify(resendPayload),
    });
    const result = await resendRes.json();
    if (!resendRes.ok) {
      return new Response(JSON.stringify({ error: result.message || 'Resend error', details: result }), {
        status: resendRes.status, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    return new Response(JSON.stringify({ success: true, id: result.id, tracking_id }), {
      status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch(e) {
    return new Response(JSON.stringify({ error: 'Email delivery failed', message: e.message }), {
      status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}
