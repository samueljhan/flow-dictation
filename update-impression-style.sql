-- Flow Dictation — impression style update (2026-08-07)
-- Run ONCE in the Supabase SQL editor. Safe to re-run: every statement is
-- idempotent (updates match on the old text, the insert is guarded).
--
-- Brings the seeded knowledge rows in line with the impression rules now in
-- server.js: unnumbered, one item per line, and only findings that change
-- management or answer the clinical question.

-- Numbering -> one item per line
update style_guide
   set rule = 'Do not number, letter, or bullet impression items — put each item on its own line, ordered by clinical significance, most important first.'
 where section = 'impressions'
   and rule = 'Number impression items and order them by clinical significance, most important first.';

-- Selectivity rule (new — no old row to update)
insert into style_guide (section, rule)
select 'impressions', 'Include only findings that change patient management or answer the clinical question; leave incidental, chronic, and stable benign findings in the body.'
 where not exists (
   select 1 from style_guide
    where section = 'impressions'
      and rule like 'Include only findings that change patient management%'
 );

-- Drop the "1." / "2." prefixes from the phrasing examples, so the reference
-- doesn't demonstrate the numbering the style guide now forbids
update rad_language
   set content = 'Lead with the diagnosis that answers the clinical question: "Acute uncomplicated appendicitis."'
 where category = 'impression_phrasing'
   and content = 'Lead with the diagnosis that answers the clinical question: "1. Acute uncomplicated appendicitis."';

update rad_language
   set content = 'Pertinent negative phrasing when it answers the referrer: "No drainable fluid collection."'
 where category = 'impression_phrasing'
   and content = 'Pertinent negative phrasing when it answers the referrer: "2. No drainable fluid collection."';
