-- ═══════════════════════════════════════════════════════════════
-- TalentBase — Role-Based Access Control
-- Run in: Supabase Dashboard → SQL Editor
-- Safe to re-run: all statements are idempotent
-- ═══════════════════════════════════════════════════════════════

-- ── STEP 1: Add columns ───────────────────────────────────────
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS visible_to_client  boolean DEFAULT false;
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS client_company      text;

-- ── STEP 2: Drop ALL existing policies (clean slate) ─────────
DROP POLICY IF EXISTS "own_candidates"            ON candidates;
DROP POLICY IF EXISTS "own_jobs"                  ON jobs;
DROP POLICY IF EXISTS "own_deals"                 ON deals;
DROP POLICY IF EXISTS "own_activity"              ON activity;
DROP POLICY IF EXISTS "service_activity"          ON activity;
DROP POLICY IF EXISTS "client_read_candidates"    ON candidates;
DROP POLICY IF EXISTS "client_own_feedback"       ON client_feedback;
DROP POLICY IF EXISTS "admin_read_feedback"       ON client_feedback;
DROP POLICY IF EXISTS "recruiter_candidates"      ON candidates;
DROP POLICY IF EXISTS "recruiter_jobs"            ON jobs;
DROP POLICY IF EXISTS "admin_candidates"          ON candidates;
DROP POLICY IF EXISTS "admin_jobs"                ON jobs;
DROP POLICY IF EXISTS "admin_deals"               ON deals;
DROP POLICY IF EXISTS "recruiter_deals"           ON deals;
DROP POLICY IF EXISTS "admin_activity"            ON activity;
DROP POLICY IF EXISTS "recruiter_activity"        ON activity;
DROP POLICY IF EXISTS "staff_read_feedback"       ON client_feedback;

-- ── STEP 3: Helper functions ──────────────────────────────────
CREATE OR REPLACE FUNCTION current_user_role()
RETURNS text LANGUAGE sql STABLE AS $$
  SELECT coalesce(
    auth.jwt() -> 'user_metadata' ->> 'role',
    'admin'
  )
$$;

CREATE OR REPLACE FUNCTION current_user_company()
RETURNS text LANGUAGE sql STABLE AS $$
  SELECT auth.jwt() -> 'user_metadata' ->> 'client_company'
$$;

-- CRITICAL: workspace owner scoping for multi-tenant client isolation
-- Set workspace_owner_id in client user_metadata when creating client users:
--   { "role": "client", "client_company": "HiARC", "workspace_owner_id": "<admin-uuid>" }
CREATE OR REPLACE FUNCTION current_workspace_owner()
RETURNS uuid LANGUAGE sql STABLE AS $$
  SELECT nullif(
    auth.jwt() -> 'user_metadata' ->> 'workspace_owner_id',
    ''
  )::uuid
$$;

-- ── STEP 4: CANDIDATES policies ──────────────────────────────

-- Admin: full CRUD on own records only
CREATE POLICY "admin_candidates" ON candidates
  FOR ALL
  USING  (auth.uid() = user_id AND current_user_role() = 'admin')
  WITH CHECK (auth.uid() = user_id AND current_user_role() = 'admin');

-- Recruiter: full CRUD on own records only
CREATE POLICY "recruiter_candidates" ON candidates
  FOR ALL
  USING  (auth.uid() = user_id AND current_user_role() = 'recruiter')
  WITH CHECK (auth.uid() = user_id AND current_user_role() = 'recruiter');

-- Client: SELECT only
--   MUST match: visible_to_client=true + client_company + workspace_owner_id
--   workspace_owner_id prevents cross-workspace leaks in multi-tenant deployments
CREATE POLICY "client_read_candidates" ON candidates
  FOR SELECT
  USING (
    current_user_role() = 'client'
    AND visible_to_client = true
    AND (
      current_workspace_owner() IS NULL          -- fallback if not set
      OR user_id = current_workspace_owner()     -- lock to one workspace
    )
    AND (
      current_user_company() IS NULL
      OR client_company = current_user_company()
    )
  );

-- ── STEP 5: JOBS policies ─────────────────────────────────────

CREATE POLICY "admin_jobs" ON jobs
  FOR ALL
  USING  (auth.uid() = user_id AND current_user_role() = 'admin')
  WITH CHECK (auth.uid() = user_id AND current_user_role() = 'admin');

CREATE POLICY "recruiter_jobs" ON jobs
  FOR ALL
  USING  (auth.uid() = user_id AND current_user_role() = 'recruiter')
  WITH CHECK (auth.uid() = user_id AND current_user_role() = 'recruiter');

-- Clients have no policy on jobs → zero rows returned (correct)

-- ── STEP 6: DEALS policies ────────────────────────────────────

CREATE POLICY "admin_deals" ON deals
  FOR ALL
  USING  (auth.uid() = user_id AND current_user_role() = 'admin')
  WITH CHECK (auth.uid() = user_id AND current_user_role() = 'admin');

CREATE POLICY "recruiter_deals" ON deals
  FOR ALL
  USING  (auth.uid() = user_id AND current_user_role() = 'recruiter')
  WITH CHECK (auth.uid() = user_id AND current_user_role() = 'recruiter');

-- ── STEP 7: ACTIVITY policies ─────────────────────────────────

CREATE POLICY "admin_activity" ON activity
  FOR ALL
  USING  (auth.uid() = user_id AND current_user_role() = 'admin')
  WITH CHECK (auth.uid() = user_id AND current_user_role() = 'admin');

CREATE POLICY "recruiter_activity" ON activity
  FOR ALL
  USING  (auth.uid() = user_id AND current_user_role() = 'recruiter')
  WITH CHECK (auth.uid() = user_id AND current_user_role() = 'recruiter');

-- Service role (Vercel track-open + email-webhook) bypasses RLS automatically.
-- No INSERT policy needed for the service role key.
-- Anon/authenticated role still needs one for direct client inserts (none allowed):
-- No "service_activity" INSERT policy = only service_role key can insert.

-- ── STEP 8: CLIENT FEEDBACK policies ─────────────────────────

CREATE POLICY "client_own_feedback" ON client_feedback
  FOR ALL
  USING  (auth.uid() = client_user_id)
  WITH CHECK (auth.uid() = client_user_id);

CREATE POLICY "staff_read_feedback" ON client_feedback
  FOR SELECT
  USING (current_user_role() IN ('admin', 'recruiter'));

-- ── STEP 9: RLS enabled (idempotent) ─────────────────────────
ALTER TABLE candidates      ENABLE ROW LEVEL SECURITY;
ALTER TABLE jobs            ENABLE ROW LEVEL SECURITY;
ALTER TABLE deals           ENABLE ROW LEVEL SECURITY;
ALTER TABLE activity        ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_feedback ENABLE ROW LEVEL SECURITY;

-- ── STEP 10: How to create user accounts ─────────────────────
--
-- ADMIN (you):
--   Auth → Users → Add User
--   User Metadata: { "role": "admin" }
--
-- RECRUITER:
--   User Metadata: { "role": "recruiter" }
--
-- CLIENT (e.g. HiARC, scoped to your workspace):
--   User Metadata: {
--     "role": "client",
--     "client_company": "HiARC",
--     "workspace_owner_id": "<your-admin-user-uuid>"
--   }
--   Replace <your-admin-user-uuid> with your actual UUID from Auth → Users
--
-- Mark candidates visible to HiARC:
--   UPDATE candidates
--   SET visible_to_client = true, client_company = 'HiARC'
--   WHERE id IN ('id1', 'id2', 'id3');

-- ── VERIFY ────────────────────────────────────────────────────
-- SELECT tablename, policyname, cmd
-- FROM pg_policies
-- WHERE tablename IN ('candidates','jobs','deals','activity','client_feedback')
-- ORDER BY tablename, policyname;
