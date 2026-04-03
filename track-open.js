// api/track-open.js — Vercel Edge Function
// Receives open-tracking pixel requests, logs to Supabase, returns 1x1 GIF.
// URL format: /api/track-open?id=<candidateId>-<timestamp>&uid=<userId>
// Set SUPABASE_URL and SUPABASE_SERVICE_KEY in Vercel env vars.
// Use the SERVICE key (not anon) so server writes bypass RLS safely.

export const config = { runtime: 'edge' };

// Minimal 1×1 transparent GIF (base64)
const PIXEL_GIF = 'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';

export default async function handler(req) {
  const url    = new URL(req.url);
  const rawId  = url.searchParams.get('id')  || '';
  const userId = url.searchParams.get('uid') || null;

  // Always respond with the pixel immediately — never block the email client
  const respond = () => new Response(
    Buffer.from(PIXEL_GIF, 'base64'),
    { status: 200, headers: {
      'Content-Type'  : 'image/gif',
      'Cache-Control' : 'no-store, no-cache, must-revalidate, max-age=0',
      'Pragma'        : 'no-cache',
    }}
  );

  // Parse trackingId: format is "<candidateId>-<timestamp>"
  const dashIdx    = rawId.lastIndexOf('-');
  const candidateId = dashIdx > 0 ? rawId.slice(0, dashIdx) : rawId;
  const timestamp   = dashIdx > 0 ? rawId.slice(dashIdx + 1) : '';

  if (!candidateId) return respond();

  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY; // service role — bypasses RLS

  if (!SUPABASE_URL || !SUPABASE_KEY) {
    console.warn('[track-open] Supabase env vars not set');
    return respond();
  }

  // Fire-and-forget: don't await so pixel returns instantly
  (async () => {
    try {
      // 1. Log activity
      await fetch(`${SUPABASE_URL}/rest/v1/activity`, {
        method : 'POST',
        headers: {
          'apikey'       : SUPABASE_KEY,
          'Authorization': `Bearer ${SUPABASE_KEY}`,
          'Content-Type' : 'application/json',
          'Prefer'       : 'return=minimal',
        },
        body: JSON.stringify({
          candidate_id: candidateId,
          user_id     : userId,
          text        : 'Email opened',
          tracking_id : rawId,
          created_at  : new Date().toISOString(),
        }),
      });

      // 2. Update candidate opened flag + boost engagementScore
      // Read current candidate data first
      const getRes = await fetch(
        `${SUPABASE_URL}/rest/v1/candidates?id=eq.${encodeURIComponent(candidateId)}&select=id,data`,
        { headers: { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}` } }
      );
      const rows = await getRes.json();
      if (rows && rows[0]) {
        const candData = rows[0].data || {};
        // Only boost if not already marked opened (de-dupe pixel fires)
        if (!candData.opened) {
          candData.opened           = true;
          candData.openedAt         = Date.now();
          candData.engagementBoost  = (candData.engagementBoost || 0) + 10;
          if (!candData.activity) candData.activity = [];
          candData.activity.push({ ts: Date.now(), text: 'Email opened (tracked)' });

          await fetch(`${SUPABASE_URL}/rest/v1/candidates?id=eq.${encodeURIComponent(candidateId)}`, {
            method : 'PATCH',
            headers: {
              'apikey'       : SUPABASE_KEY,
              'Authorization': `Bearer ${SUPABASE_KEY}`,
              'Content-Type' : 'application/json',
              'Prefer'       : 'return=minimal',
            },
            body: JSON.stringify({ data: candData }),
          });
        }
      }
    } catch(e) {
      console.error('[track-open] Supabase update failed:', e.message);
      // Never throws — pixel already sent
    }
  })();

  return respond();
}
