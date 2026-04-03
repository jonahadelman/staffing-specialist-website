-- ═══════════════════════════════════════════════════════════════
-- TalentBase — Supabase RLS Policies
-- Run this in Supabase SQL Editor (Dashboard → SQL Editor)
-- ═══════════════════════════════════════════════════════════════

-- ── STEP 1: Add created_at column for query ordering ──────────
-- (only needed if column doesn't exist yet)
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();
ALTER TABLE jobs       ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();
ALTER TABLE deals      ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();
ALTER TABLE activity   ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();

-- ── STEP 2: Enable RLS on all tables ─────────────────────────
ALTER TABLE candidates ENABLE ROW LEVEL SECURITY;
ALTER TABLE jobs       ENABLE ROW LEVEL SECURITY;
ALTER TABLE deals      ENABLE ROW LEVEL SECURITY;
ALTER TABLE activity   ENABLE ROW LEVEL SECURITY;

-- ── STEP 3: Admin/recruiter policies ─────────────────────────
-- Only see your own records. user_id must match auth.uid().

DROP POLICY IF EXISTS "own_candidates" ON candidates;
CREATE POLICY "own_candidates" ON candidates
  FOR ALL USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "own_jobs" ON jobs;
CREATE POLICY "own_jobs" ON jobs
  FOR ALL USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "own_deals" ON deals;
CREATE POLICY "own_deals" ON deals
  FOR ALL USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "own_activity" ON activity;
CREATE POLICY "own_activity" ON activity
  FOR ALL USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- ── STEP 4: Add visible_to_client column ─────────────────────
-- Lets you flag specific candidates as visible in the client portal.
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS visible_to_client BOOLEAN DEFAULT false;

-- ── STEP 5: Client portal policy ─────────────────────────────
-- Client users can only read candidates where visible_to_client = true.
-- Their JWT must contain user_metadata.role = 'client'.
-- Set this in Supabase Dashboard → Authentication → Users → Edit → Custom Claims

DROP POLICY IF EXISTS "client_read_candidates" ON candidates;
CREATE POLICY "client_read_candidates" ON candidates
  FOR SELECT USING (
    visible_to_client = true
    AND (auth.jwt() -> 'user_metadata' ->> 'role') = 'client'
  );

-- ── STEP 6: client_feedback table ────────────────────────────
-- Client approvals/declines/notes are stored here, not in the main candidates table.
CREATE TABLE IF NOT EXISTS client_feedback (
  id            UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  candidate_id  TEXT NOT NULL,
  client_user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  decision      TEXT,    -- 'approve' | 'reject'
  note          TEXT,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE client_feedback ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "client_own_feedback" ON client_feedback;
CREATE POLICY "client_own_feedback" ON client_feedback
  FOR ALL USING (auth.uid() = client_user_id)
  WITH CHECK (auth.uid() = client_user_id);

-- Admins can read all feedback for their candidates
DROP POLICY IF EXISTS "admin_read_feedback" ON client_feedback;
CREATE POLICY "admin_read_feedback" ON client_feedback
  FOR SELECT USING (
    (auth.jwt() -> 'user_metadata' ->> 'role') = 'admin'
    OR (auth.jwt() -> 'user_metadata' ->> 'role') IS NULL
  );

-- ── STEP 7: Service role bypass for tracking webhooks ─────────
-- track-open.js and email-webhook.js use SUPABASE_SERVICE_KEY.
-- The service role bypasses RLS automatically — no policy needed.
-- Just make sure SUPABASE_SERVICE_KEY is set in Vercel env vars
-- and is NEVER exposed client-side.

-- ── STEP 8: How to create a client user ──────────────────────
-- 1. Go to Supabase Dashboard → Authentication → Users → Add User
-- 2. Enter client's email + temp password
-- 3. After creation, click the user → Edit → User Metadata:
--    { "role": "client", "client_name": "HiARC" }
-- 4. Send client the URL: https://yoursite.com/TalentBase_TheStaffingSpecialist.html?view=client
-- 5. They log in with their email/password
-- 6. They see ONLY candidates where visible_to_client = true

-- ── STEP 9: Mark a candidate as client-visible ───────────────
-- From Supabase SQL Editor or from TalentBase (future UI):
-- UPDATE candidates SET visible_to_client = true WHERE id = 'CANDIDATE_ID';

-- ── VERIFICATION ─────────────────────────────────────────────
-- Run these to confirm policies are active:
SELECT tablename, policyname, cmd FROM pg_policies
WHERE tablename IN ('candidates','jobs','deals','activity','client_feedback')
ORDER BY tablename, policyname;
