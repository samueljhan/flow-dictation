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
  -- RPR attending-comparison grading (auto-graded on final save, manual override allowed)
  -- RPR1 concordant · RPR2 minor · RPR3 possibly significant · RPR4 clinically significant
  rpr_grade text check (rpr_grade in ('RPR1', 'RPR2', 'RPR3', 'RPR4')),
  rpr_rationale text
);

-- If the reports table already exists, run these instead of re-creating it:
-- alter table reports add column if not exists rpr_grade text check (rpr_grade in ('RPR1', 'RPR2', 'RPR3', 'RPR4'));
-- alter table reports add column if not exists rpr_rationale text;

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
