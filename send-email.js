// api/send-email.js — Vercel Serverless Function
// Proxies email sends to Resend. Keeps API key server-side only.
// Deploy: push to GitHub → Vercel picks this up automatically.
// Set RESEND_API_KEY in Vercel project environment variables.

export const config = { runtime: 'edge' };

const ALLOWED_ORIGINS = [
  'https://www.thestaffingspecialist.com',
  'https://thestaffingspecialist.com',
  // Add your Vercel preview URLs here if needed
];

export default async function handler(req) {
  // CORS preflight
  const origin = req.headers.get('origin') || '';
  const corsHeaders = {
    'Access-Control-Allow-Origin': ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0],
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };

  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }
  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }

  const RESEND_KEY = process.env.RESEND_API_KEY;
  if (!RESEND_KEY) {
    return new Response(JSON.stringify({ error: 'Email service not configured' }), {
      status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }

  let body;
  try { body = await req.json(); } catch(e) {
    return new Response(JSON.stringify({ error: 'Invalid request body' }), {
      status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }

  const { to, subject, html, text, from_name, tags, tracking_id } = body;

  // Validate required fields
  if (!to || !subject || (!html && !text)) {
    return new Response(JSON.stringify({ error: 'Missing required fields: to, subject, html/text' }), {
      status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }

  // Validate recipient email format
  if (typeof to === 'string' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) {
    return new Response(JSON.stringify({ error: 'Invalid recipient email address' }), {
      status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }

  try {
    // Build Resend payload — include tags for webhook correlation
    const resendPayload = {
      from   : `${from_name || 'Jonah Adelman'} <onboarding@resend.dev>`,
      to     : Array.isArray(to) ? to : [to],
      subject,
      html   : html || `<pre style="font-family:sans-serif">${text}</pre>`,
      text   : text || html?.replace(/<[^>]+>/g, '') || '',
    };
    // Pass tracking tag through so email-webhook.js can correlate events
    if (tags && Array.isArray(tags) && tags.length) resendPayload.tags = tags;
    else if (tracking_id) resendPayload.tags = [{ name: 'tracking_id', value: String(tracking_id) }];

    const resendRes = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${RESEND_KEY}`,
        'Content-Type' : 'application/json',
      },
      body: JSON.stringify(resendPayload),
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
