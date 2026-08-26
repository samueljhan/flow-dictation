-- Flow Dictation — Supabase schema
-- Run this in the Supabase dashboard SQL editor.

-- Shifts: created only via "Start New Shift" (or silently on first-ever save).
-- is_active marks the current shift server-side (see the Active shift section
-- below for the uniqueness index and backfill).
create table if not exists shifts (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  started_at timestamptz not null default now(),
  last_activity_at timestamptz not null default now(),
  is_active boolean not null default false
);

-- Historical study types for the Draft page combobox (ordered by most recently used)
create table if not exists study_types (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  last_used_at timestamptz not null default now()
);

-- Reports. id is the yyyymmddhhmm save timestamp (with -2/-3... suffix on collision)
create table if not exists reports (
  id text primary key,
  shift_id uuid references shifts(id),
  study_type text,
  study_id_label text,
  report_type text not null default 'complete' check (report_type in ('prelim', 'complete')),
  raw_text text not null,
  draft_text text not null,
  edits_json jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now(),
  final_text text,
  final_saved_at timestamptz,
  -- Read-out: verbal attending feedback jotted per study, and when (if ever)
  -- it was integrated into the draft via edit cards
  readout_notes text,
  notes_integrated_at timestamptz,
  -- RPR grade as ACTUALLY assigned by the attending/QA — manual documentation only,
  -- never AI-generated. RPR1 concordant · RPR2 minor discrepancy, unlikely clinical
  -- significance · RPR3 moderate, possible significance · RPR4 major, likely significance
  rpr_grade text check (rpr_grade in ('RPR1', 'RPR2', 'RPR3', 'RPR4')),
  rpr_note text   -- "what I missed / lesson" free text
);

-- If the reports table already exists, run these instead of re-creating it:
-- alter table reports add column if not exists rpr_grade text check (rpr_grade in ('RPR1', 'RPR2', 'RPR3', 'RPR4'));
-- alter table reports add column if not exists rpr_note text;
-- If upgrading from the AI-grading version (column was rpr_rationale):
-- alter table reports rename column rpr_rationale to rpr_note;
-- Optionally wipe old AI-generated grades/rationales so only real attending grades remain:
-- update reports set rpr_grade = null, rpr_note = null;

create index if not exists reports_shift_id_idx on reports (shift_id, created_at desc);

-- Assist page feedback (thumbs up/down + optional comment per response)
create table if not exists assist_feedback (
  id uuid primary key default gen_random_uuid(),
  timestamp timestamptz not null default now(),
  action_type text,          -- describe | reword | proofread | impression | freeform
  user_input text,
  model_response text,
  rating text check (rating in ('up', 'down')),
  comment text
);

-- The server uses the service-role key, which bypasses RLS. Enable RLS so the
-- anon key (if ever exposed) cannot read these tables directly.
alter table shifts enable row level security;
alter table study_types enable row level security;
alter table reports enable row level security;
alter table assist_feedback enable row level security;

-- ============================================================
-- Read-out workflow (added later — run this section on its own if
-- the tables above already exist in your database)
-- ============================================================

alter table reports add column if not exists readout_notes text;
alter table reports add column if not exists notes_integrated_at timestamptz;

-- Drives the Draft list dots: read_out_at (manually marked as read out with the
-- attending) and finalized_at ("Save Final" — done, sorts to the bottom).
alter table reports add column if not exists read_out_at timestamptz;
alter table reports add column if not exists finalized_at timestamptz;

-- Section (subspecialty) — manual only, set once per shift. The shift carries
-- the current setting (shifts.subspecialty) and every report save stamps it
-- onto the report at that moment; reports.subspecialty stays the source of
-- truth for filtering. The stamp is written once — changing the shift's
-- section mid-way never rewrites earlier cases. Never derived, mapped, or
-- backfilled. Free text typed via "Other" is stored verbatim.
alter table reports add column if not exists subspecialty text;
create index if not exists reports_subspecialty_idx on reports (subspecialty);
alter table report_sections add column if not exists subspecialty text;
alter table shifts add column if not exists subspecialty text;

-- Finalized reports kept whole, alongside their findings/impression split when
-- those sections can be detected. One row per report, so a findings+impression
-- pair is intrinsically matched and ready to export as training data.
-- findings/impression are nullable on purpose: a prelim that is impression-only
-- (or any report whose headings don't parse) is still stored in full.
create table if not exists report_sections (
  id bigint generated always as identity primary key,
  report_id text not null references reports(id) on delete cascade,
  source text not null default 'final',      -- which text it came from: 'final' | 'draft'
  study_type text,
  full_text text not null,                   -- always the complete report
  findings text,                             -- null when no FINDINGS section was found
  impression text,                           -- null when no IMPRESSION section was found
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (report_id, source)                 -- re-saving a final updates its row
);
create index if not exists report_sections_study_type_idx on report_sections (study_type);
-- Complete pairs are what training reads; index them for that query
create index if not exists report_sections_paired_idx on report_sections (created_at desc)
  where findings is not null and impression is not null;
alter table report_sections enable row level security;

-- Previous draft_text values, written on every re-save, so "See recent changes"
-- can diff the current draft against the one before it.
create table if not exists report_revisions (
  id bigint generated always as identity primary key,
  report_id text not null references reports(id) on delete cascade,
  draft_text text not null,
  created_at timestamptz not null default now()
);
create index if not exists report_revisions_report_idx on report_revisions (report_id, id desc);
alter table report_revisions enable row level security;

-- ============================================================
-- Active shift (added later — run this section on its own if the
-- tables above already exist in your database)
-- ============================================================

-- The "current shift" selection lives server-side so every browser/device
-- agrees on it. The partial unique index makes >1 active shift impossible
-- at the database level.
alter table shifts add column if not exists is_active boolean not null default false;
create unique index if not exists one_active_shift on shifts (is_active) where is_active;

-- Backfill: if nothing is active yet, activate the most recently started shift
update shifts set is_active = true
where id = (select id from shifts order by started_at desc limit 1)
  and not exists (select 1 from shifts where is_active);

-- ============================================================
-- Assist chat history (added later — run this section on its own
-- if the tables above already exist in your database)
-- ============================================================

-- Persistent Assist chat log. Server-side so history follows the login across
-- browsers/devices. Never cleared by the app. bigint identity id gives a
-- guaranteed insert order even when a user+assistant pair shares a timestamp.
create table if not exists assist_messages (
  id bigint generated always as identity primary key,
  role text not null check (role in ('user', 'assistant')),
  content text not null,
  action_type text,          -- describe | reword | proofread | impression | fullreport | synthesize | freeform
                             -- ('radqa' appears in rows saved before the Quick Rad Question action was removed)
  created_at timestamptz not null default now()
);

alter table assist_messages enable row level security;

-- ============================================================
-- Knowledge layer (added later — run this section on its own if
-- the tables above already exist in your database)
-- ============================================================

-- Exemplar reports: user-pasted gold-standard reports + imported PARROT reports
create table if not exists exemplar_reports (
  id uuid primary key default gen_random_uuid(),
  study_type text,
  title text,
  body text not null,
  notes text,
  source text not null default 'user',   -- 'user' | 'parrot'
  created_at timestamptz not null default now()
);
create index if not exists exemplar_reports_study_type_idx on exemplar_reports (study_type);
create index if not exists exemplar_reports_source_idx on exemplar_reports (source);

-- Reporting style rules, grouped by section (e.g. general, findings, impressions)
create table if not exists style_guide (
  id uuid primary key default gen_random_uuid(),
  section text not null default 'general',
  rule text not null,
  created_at timestamptz not null default now()
);

-- Radiology register/phrasing reference entries
-- categories: findings_phrasing, impression_phrasing, hedging, negatives,
--             measurements, comparison, modality_conventions, words_to_avoid
create table if not exists rad_language (
  id uuid primary key default gen_random_uuid(),
  category text not null,
  content text not null,
  created_at timestamptz not null default now()
);

alter table exemplar_reports enable row level security;
alter table style_guide enable row level security;
alter table rad_language enable row level security;

-- ============================================================
-- Review-quality telemetry (added 2026-08 — run this section on
-- its own if the tables above already exist). The server also
-- ensures this schema at startup, so running it manually is a
-- no-op safety net.
-- ============================================================

-- One row per Review/read-out suggestion at generation time, including
-- suggestions the server dropped in validation (disposition
-- 'dropped_validation' — the fabrication-rate metric). edits_json on reports
-- stays the app's working copy; this table is the analytics layer.
create table if not exists review_events (
  id bigint generated always as identity primary key,
  report_id text not null references reports(id) on delete cascade,
  source text not null check (source in ('review', 'readout')),
  model text,
  batch_id uuid not null,               -- groups one model call's suggestions
  latency_ms int,                       -- model call wall time; identical across a batch
  created_at timestamptz not null default now(),
  category text,
  target_section text,
  original_text text,
  suggested_text text,
  reason text,
  evidence_impression text,
  evidence_findings text,
  disposition text check (disposition in
    ('accepted', 'rejected', 'edited', 'dropped_validation', 'undecided')),
  adopted_text text,                    -- what was applied when disposition='edited'
  helpful boolean,                      -- 👍/👎 on the suggestion itself
  feedback_note text,                   -- optional short comment
  decided_at timestamptz,
  scrubbed_at timestamptz               -- set by the finalization scrub
);
create index if not exists review_events_report_idx on review_events (report_id);
create index if not exists review_events_disposition_idx on review_events (disposition);
create index if not exists review_events_category_idx on review_events (category);
create index if not exists review_events_created_idx on review_events (created_at);
alter table review_events enable row level security;

-- Assist feedback gains the same model/latency telemetry
alter table assist_feedback add column if not exists model text;
alter table assist_feedback add column if not exists latency_ms int;
