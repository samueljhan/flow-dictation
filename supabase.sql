-- Flow Dictation — Supabase schema
-- Run this in the Supabase dashboard SQL editor.

-- Shifts: created only via "Start New Shift" (or silently on first-ever save)
create table if not exists shifts (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  started_at timestamptz not null default now(),
  last_activity_at timestamptz not null default now()
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
