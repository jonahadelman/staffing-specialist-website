// api/send-email.js — Vercel Edge Function
// Proxies email sends to Resend. Keeps API key server-side only.
//
// REQUIRED Vercel env vars:
//   RESEND_API_KEY  — your Resend key
//   EMAIL_SECRET    — shared secret (openssl rand -hex 32)
//                     also stored in TalentBase Settings → Email
//
// SECURITY MODEL:
//   1. EMAIL_SECRET is REQUIRED — missing env var = 503, not open endpoint
//   2. x-tb-secret header must match exactly
//   3. Per-IP rate limit: 10 emails/min (in-memory, resets on cold start)
//   4. Request body capped at 64KB
//   5. html + text fields capped at 50KB each
//   6. Recipient cap: 10 per call (recruiter use case, not bulk blast)
//   7. Subject line capped at 200 chars
//   8. CORS origin allowlist enforced

export const config = { runtime: 'edge' };

const ALLOWED_ORIGINS = [
  'https://www.thestaffingspecialist.com',
  'https://thestaffingspecialist.com',
];

const MAX_BODY_BYTES    = 64 * 1024;       // 64 KB total body
const MAX_HTML_BYTES    = 50 * 1024;       // 50 KB html/text field
const MAX_RECIPIENTS    = 10;              // per-call recipient cap
const MAX_SUBJECT_LEN   = 200;
const RATE_LIMIT        = 10;              // requests per window per IP
const RATE_WINDOW_MS    = 60_000;          // 60 seconds
const EMAIL_RE          = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{1,63}$/;

// ── IN-MEMORY RATE LIMITER ────────────────────────────────────
// Resets on cold start. Acceptable for edge: provides burst protection
// within a warm instance. PRIMARY protection is the shared secret.
const _buckets = new Map();
function checkRate(ip) {
  const now = Date.now();
  let b = _buckets.get(ip);
  if (!b || now > b.reset) b = { count: 0, reset: now + RATE_WINDOW_MS };
  b.count++;
  _buckets.set(ip, b);
  return { allowed: b.count <= RATE_LIMIT, remaining: Math.max(0, RATE_LIMIT - b.count) };
}

// ── HELPERS ───────────────────────────────────────────────────
function json(data, status, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...extra },
  });
}

function byteLen(str) {
  // TextEncoder gives exact UTF-8 byte count
  return new TextEncoder().encode(str).length;
}

// ── HANDLER ──────────────────────────────────────────────────
export default async function handler(req) {
  const origin = req.headers.get('origin') || '';
  const allowedOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  const cors = {
    'Access-Control-Allow-Origin' : allowedOrigin,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, x-tb-secret',
    'Vary'                        : 'Origin',
  };

  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: cors });
  }
  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405, headers: { ...cors, 'Content-Type': 'application/json' },
    });
  }

  // ── 1. SECRET AUTH — hard required, not optional ─────────────
  const EMAIL_SECRET = process.env.EMAIL_SECRET;
  if (!EMAIL_SECRET) {
    // Env var not set at all — refuse all requests rather than being open
    return new Response(JSON.stringify({ error: 'Email service not configured' }), {
      status: 503, headers: { ...cors, 'Content-Type': 'application/json' },
    });
  }
  const provided = req.headers.get('x-tb-secret') || '';
  if (provided !== EMAIL_SECRET) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401, headers: { ...cors, 'Content-Type': 'application/json' },
    });
  }

  // ── 2. RATE LIMIT ────────────────────────────────────────────
  const ip = (req.headers.get('x-forwarded-for') || '').split(',')[0].trim() || 'unknown';
  const { allowed, remaining } = checkRate(ip);
  if (!allowed) {
    return new Response(JSON.stringify({ error: 'Rate limit exceeded — try again in a minute.' }), {
      status: 429,
      headers: {
        ...cors,
        'Content-Type': 'application/json',
        'Retry-After' : '60',
        'X-RateLimit-Limit'    : String(RATE_LIMIT),
        'X-RateLimit-Remaining': '0',
      },
    });
  }

  // ── 3. BODY SIZE GUARD ───────────────────────────────────────
  const contentLength = parseInt(req.headers.get('content-length') || '0', 10);
  if (contentLength > MAX_BODY_BYTES) {
    return new Response(JSON.stringify({ error: 'Request body too large (64 KB max)' }), {
      status: 413, headers: { ...cors, 'Content-Type': 'application/json' },
    });
  }

  // ── 4. RESEND KEY ─────────────────────────────────────────────
  const RESEND_KEY = process.env.RESEND_API_KEY;
  if (!RESEND_KEY) {
    return new Response(JSON.stringify({ error: 'Resend API key not configured' }), {
      status: 503, headers: { ...cors, 'Content-Type': 'application/json' },
    });
  }

  // ── 5. PARSE + VALIDATE BODY ─────────────────────────────────
  let body;
  try {
    const raw = await req.text();
    if (byteLen(raw) > MAX_BODY_BYTES) {
      return new Response(JSON.stringify({ error: 'Request body too large (64 KB max)' }), {
        status: 413, headers: { ...cors, 'Content-Type': 'application/json' },
      });
    }
    body = JSON.parse(raw);
  } catch(e) {
    return new Response(JSON.stringify({ error: 'Invalid JSON body' }), {
      status: 400, headers: { ...cors, 'Content-Type': 'application/json' },
    });
  }

  const { to, subject, html, text, from_name, tags, tracking_id } = body;

  // Required fields
  if (!to || !subject || (!html && !text)) {
    return new Response(JSON.stringify({ error: 'Missing required fields: to, subject, and html or text' }), {
      status: 400, headers: { ...cors, 'Content-Type': 'application/json' },
    });
  }

  // Recipient count cap
  const recipients = Array.isArray(to) ? to : [to];
  if (recipients.length > MAX_RECIPIENTS) {
    return new Response(JSON.stringify({ error: `Too many recipients (max ${MAX_RECIPIENTS})` }), {
      status: 400, headers: { ...cors, 'Content-Type': 'application/json' },
    });
  }

  // Email format validation
  for (const addr of recipients) {
    if (typeof addr !== 'string' || !EMAIL_RE.test(addr.trim())) {
      return new Response(JSON.stringify({ error: `Invalid email address: ${String(addr).slice(0, 100)}` }), {
        status: 400, headers: { ...cors, 'Content-Type': 'application/json' },
      });
    }
  }

  // Field size caps — prevent oversized content reaching Resend
  const subjectStr  = String(subject).slice(0, MAX_SUBJECT_LEN);
  const fromNameStr = String(from_name || 'Jonah Adelman').slice(0, 100);

  if (html && byteLen(html) > MAX_HTML_BYTES) {
    return new Response(JSON.stringify({ error: 'html field exceeds 50 KB limit' }), {
      status: 400, headers: { ...cors, 'Content-Type': 'application/json' },
    });
  }
  if (text && byteLen(text) > MAX_HTML_BYTES) {
    return new Response(JSON.stringify({ error: 'text field exceeds 50 KB limit' }), {
      status: 400, headers: { ...cors, 'Content-Type': 'application/json' },
    });
  }

  // ── 6. BUILD + SEND ───────────────────────────────────────────
  try {
    const resendPayload = {
      from   : `${fromNameStr} <onboarding@resend.dev>`,
      to     : recipients.map(a => a.trim()),
      subject: subjectStr,
      html   : html   || `<pre style="font-family:sans-serif;white-space:pre-wrap">${text}</pre>`,
      text   : text   || (html || '').replace(/<[^>]+>/g, ''),
    };

    // Tags: validate structure, cap count and value lengths
    if (tracking_id) {
      resendPayload.tags = [{
        name : 'tracking_id',
        value: String(tracking_id).replace(/[^a-zA-Z0-9_\-]/g, '').slice(0, 256),
      }];
    } else if (Array.isArray(tags) && tags.length) {
      resendPayload.tags = tags
        .slice(0, 5)
        .filter(t => t && typeof t.name === 'string' && typeof t.value === 'string')
        .map(t => ({ name: t.name.slice(0, 64), value: t.value.slice(0, 256) }));
    }

    const resendRes = await fetch('https://api.resend.com/emails', {
      method : 'POST',
      headers: {
        'Authorization': `Bearer ${RESEND_KEY}`,
        'Content-Type' : 'application/json',
      },
      body: JSON.stringify(resendPayload),
    });

    const result = await resendRes.json();
    if (!resendRes.ok) {
      return new Response(JSON.stringify({ error: result.message || 'Resend error', code: result.name }), {
        status: resendRes.status, headers: { ...cors, 'Content-Type': 'application/json' },
      });
    }

    return new Response(JSON.stringify({ success: true, id: result.id, tracking_id }), {
      status: 200,
      headers: {
        ...cors,
        'Content-Type'         : 'application/json',
        'X-RateLimit-Limit'    : String(RATE_LIMIT),
        'X-RateLimit-Remaining': String(remaining),
      },
    });

  } catch(e) {
    return new Response(JSON.stringify({ error: 'Email delivery failed', message: e.message }), {
      status: 502, headers: { ...cors, 'Content-Type': 'application/json' },
    });
  }
}
