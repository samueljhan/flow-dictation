#!/usr/bin/env node
// Import the PARROT v1.0 dataset into exemplar_reports (source='parrot').
//
// PARROT v1.0: fictional radiology reports written by real radiologists.
// https://github.com/PARROT-reports/PARROT_v1.0 — CC BY-NC-SA 4.0 (non-commercial).
//
// NOTE ON LANGUAGE: the dataset contains NO English-original reports — all 2,738
// records are non-English (Polish, French, German, ...) with an English
// `translation` field. So by default this script imports the English
// TRANSLATION text. Pass --original-only to import only English-language
// originals (currently imports nothing; future-proofing).
//
// Usage:
//   npm run import-parrot            # import English translations (default)
//   node scripts/import-parrot.js --original-only
//   node scripts/import-parrot.js --limit 100   # for testing
//
// Idempotent: entries whose PARROT title already exists are skipped.

require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

const DATA_URL = 'https://raw.githubusercontent.com/PARROT-reports/PARROT_v1.0/main/data/PARROT_v1_0.jsonl';
const MIN_CHARS = 200;
const BATCH_SIZE = 50;

const args = process.argv.slice(2);
const ORIGINAL_ONLY = args.includes('--original-only');
const limitIdx = args.indexOf('--limit');
const LIMIT = limitIdx !== -1 ? parseInt(args[limitIdx + 1], 10) : Infinity;

// Deterministic modality mapping (actual codes observed in the dataset).
// OPH (ophthalmic imaging) and ENDOSCOPY are skipped — not radiology reports.
const MODALITY_MAP = {
  'MR': 'MRI',
  'CT': 'CT',
  'RX': 'XR',
  'US': 'US',
  'MG': 'MG',
  'XA': 'XA',
  'PET/CT': 'PET/CT'
};

// Deterministic area cleanup for typos/synonyms observed in the dataset
const AREA_FIXES = {
  'lumber spine': 'lumbar spine',
  'lubar spine': 'lumbar spine',
  'lumbar': 'lumbar spine',
  'cervical': 'cervical spine',
  'brain': 'head',
  'head- head': 'head',
  'head native': 'head',
  'ear': 'ears',
  'lower limb': 'lower limbs',
  'upper limb': 'upper limbs',
  'upper extremity': 'upper limbs',
  'pituitary gland': 'pituitary'
};

function normalizeStudyType(modality, area) {
  const mod = MODALITY_MAP[(modality || '').trim().toUpperCase()];
  if (!mod) return null; // unmapped modality → skip record
  const parts = String(area || '')
    .toLowerCase()
    .replace(/[\n\-]+/g, ',')
    .replace(/\band\b/g, ',')
    .split(',')
    .map(p => p.replace(/\s+/g, ' ').trim())
    .filter(Boolean)
    .map(p => AREA_FIXES[p] || p);
  const deduped = [...new Set(parts)];
  if (deduped.length === 0) return mod;
  return mod + ' ' + deduped.join(' ');
}

async function main() {
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
    console.error('Missing SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY in environment.');
    process.exit(1);
  }
  const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false }
  });

  console.log('Downloading PARROT v1.0 …');
  const resp = await fetch(DATA_URL);
  if (!resp.ok) {
    console.error(`Download failed: HTTP ${resp.status} from ${DATA_URL}`);
    process.exit(1);
  }
  const jsonl = await resp.text();
  const lines = jsonl.split('\n').filter(l => l.trim());
  console.log(`Downloaded ${lines.length} records.`);

  // Existing PARROT titles for idempotency (paged past Supabase's 1000-row cap)
  const existing = new Set();
  for (let from = 0; ; from += 1000) {
    const { data, error } = await supabase
      .from('exemplar_reports')
      .select('title')
      .eq('source', 'parrot')
      .range(from, from + 999);
    if (error) { console.error('Failed to read existing rows:', error.message); process.exit(1); }
    data.forEach(r => existing.add(r.title));
    if (data.length < 1000) break;
  }
  console.log(`${existing.size} PARROT exemplars already in the database.`);

  const rows = [];
  const skipped = { modality: 0, short: 0, language: 0, existing: 0, parseError: 0 };

  for (const line of lines) {
    if (rows.length >= LIMIT) break;
    let r;
    try { r = JSON.parse(line); } catch (e) { skipped.parseError++; continue; }

    const isEnglish = (r.language || '').toLowerCase().startsWith('en');
    let body;
    if (isEnglish) {
      body = (r.report || '').trim();
    } else if (!ORIGINAL_ONLY) {
      body = (r.translation || '').trim(); // English translation of a non-English report
    } else {
      skipped.language++;
      continue;
    }
    if (body.length < MIN_CHARS) { skipped.short++; continue; }

    const studyType = normalizeStudyType(r.modality, r.area);
    if (!studyType) { skipped.modality++; continue; }

    const title = `PARROT #${r.no} ${studyType}`;
    if (existing.has(title)) { skipped.existing++; continue; }
    existing.add(title); // guard against duplicate `no` within one run

    rows.push({
      study_type: studyType,
      title,
      body,
      notes: `PARROT v1.0, ${r.country || 'unknown country'}, subspecialty ${r.subspecialty || 'unknown'}. CC BY-NC-SA 4.0 — non-commercial.`,
      source: 'parrot'
    });
  }

  console.log(`Prepared ${rows.length} new exemplars. Skipped: ${JSON.stringify(skipped)}`);

  let inserted = 0;
  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    const batch = rows.slice(i, i + BATCH_SIZE);
    const { error } = await supabase.from('exemplar_reports').insert(batch);
    if (error) {
      console.error(`Batch ${i / BATCH_SIZE + 1} failed:`, error.message);
      process.exit(1);
    }
    inserted += batch.length;
    process.stdout.write(`\rInserted ${inserted}/${rows.length}`);
  }
  console.log('\nDone.');

  // Summary counts by study_type
  const counts = {};
  rows.forEach(r => { counts[r.study_type] = (counts[r.study_type] || 0) + 1; });
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  console.log('\nImported this run, by study type:');
  for (const [st, n] of sorted) console.log(`  ${String(n).padStart(4)}  ${st}`);
  console.log(`  ----\n  ${String(inserted).padStart(4)}  total`);
}

main().catch(e => { console.error(e); process.exit(1); });
