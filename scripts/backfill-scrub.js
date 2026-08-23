#!/usr/bin/env node
// One-time backfill: run the full PHI scrub (pattern + model pass) over every
// report that already HAS a final (those are done; in-progress drafts stay
// untouched), including its revisions, edits_json, and report_sections rows.
// Prints replacement counts by TYPE per report id for spot-checking — never
// the matched text.
//
// Usage (cloud-sql-proxy running, PG* + GOOGLE_CLOUD_PROJECT set):
//   node scripts/backfill-scrub.js --dry-run   # counts only, no writes
//   node scripts/backfill-scrub.js             # scrub and write
//   node scripts/backfill-scrub.js --force     # include already-scrubbed reports
require('dotenv').config();
const db = require('../db');
const gemini = require('../gemini');
const scrub = require('./../scrub');

const DRY = process.argv.includes('--dry-run');
const FORCE = process.argv.includes('--force');

async function modelFindPhi(text) {
  const r = await gemini.generate({
    model: process.env.MODEL_SCRUB || 'gemini-2.5-flash-lite',
    system: scrub.SCRUB_SYSTEM,
    contents: [{ role: 'user', parts: [{ text }] }],
    maxTokens: 8000,
    effort: 'low',
    responseSchema: scrub.SCRUB_SCHEMA
  });
  const parsed = JSON.parse(r.text);
  return Array.isArray(parsed.replacements) ? parsed.replacements : [];
}

async function scrubTexts(texts) {
  const counts = {};
  const out = {};
  for (const [k, v] of Object.entries(texts)) {
    if (typeof v !== 'string' || !v) { out[k] = v; continue; }
    const r = scrub.patternScrub(v);
    out[k] = r.text;
    for (const [t, n] of Object.entries(r.counts)) counts[t] = (counts[t] || 0) + n;
  }
  let modelOk = true, modelApplied = 0, replacements = [];
  const joined = Object.values(out).filter(t => typeof t === 'string' && t.trim()).join('\n\n----- NEXT DOCUMENT -----\n\n');
  if (joined.trim()) {
    try {
      replacements = await modelFindPhi(joined);
      for (const k of Object.keys(out)) {
        if (typeof out[k] !== 'string' || !out[k]) continue;
        const r = scrub.applyReplacements(out[k], replacements);
        out[k] = r.text;
        modelApplied += r.applied;
      }
    } catch (e) {
      modelOk = false;
      console.warn(`  model pass failed (${e.message}) — pattern pass only`);
    }
  }
  return { texts: out, replacements, counts, modelOk, modelApplied };
}

function scrubEditsJson(edits, replacements) {
  return (Array.isArray(edits) ? edits : []).map(e => {
    if (!e || typeof e !== 'object') return e;
    const clean = { ...e };
    for (const f of ['original_text', 'suggested_text', 'user_text', 'reason']) {
      if (typeof clean[f] === 'string' && clean[f]) {
        clean[f] = scrub.applyReplacements(scrub.patternScrub(clean[f]).text, replacements).text;
      }
    }
    return clean;
  });
}

async function main() {
  // scrubbed_at is added by migrate-random-ids.js; tolerate a dry-run before it
  const hasCol = await db.one(
    `select 1 from information_schema.columns where table_name='reports' and column_name='scrubbed_at'`);
  if (!hasCol && !DRY) {
    console.error('reports.scrubbed_at does not exist yet — run scripts/migrate-random-ids.js first.');
    process.exit(1);
  }
  const reports = await db.many(
    `select * from reports where final_text is not null${(FORCE || !hasCol) ? '' : ' and scrubbed_at is null'} order by created_at`);
  console.log(`${reports.length} finalized report(s) to scrub${DRY ? ' (dry run)' : ''}.`);
  let ok = 0, degraded = 0;

  for (const rep of reports) {
    const revisions = await db.many(`select id, draft_text from report_revisions where report_id = $1`, [rep.id]);
    const sections = await db.many(`select id, full_text, findings, impression from report_sections where report_id = $1`, [rep.id]);
    const input = {
      raw_text: rep.raw_text,
      draft_text: rep.draft_text,
      final_text: rep.final_text,
      readout_notes: rep.readout_notes,
      ...Object.fromEntries(revisions.map(r => ['rev_' + r.id, r.draft_text])),
      ...Object.fromEntries(sections.flatMap(sec => [
        ['sec_full_' + sec.id, sec.full_text],
        ['sec_find_' + sec.id, sec.findings],
        ['sec_imp_' + sec.id, sec.impression]
      ]))
    };
    const s = await scrubTexts(input);
    console.log(`${rep.id}: pattern=${JSON.stringify(s.counts)} model_applied=${s.modelApplied} model_ok=${s.modelOk}${rep.study_id_label ? ' study_id_label->null' : ''}`);
    if (s.modelOk) ok++; else degraded++;
    if (DRY) continue;

    const now = new Date().toISOString();
    await db.tx(async client => {
      await client.query(
        `update reports set raw_text=$2, draft_text=$3, final_text=$4, readout_notes=$5,
                edits_json=$6::jsonb, study_id_label=null, scrubbed_at=$7 where id=$1`,
        [rep.id, s.texts.raw_text, s.texts.draft_text, s.texts.final_text, s.texts.readout_notes,
         JSON.stringify(scrubEditsJson(rep.edits_json, s.replacements)), s.modelOk ? now : null]);
      for (const r of revisions) {
        await client.query(`update report_revisions set draft_text=$2 where id=$1`, [r.id, s.texts['rev_' + r.id]]);
      }
      for (const sec of sections) {
        await client.query(`update report_sections set full_text=$2, findings=$3, impression=$4 where id=$1`,
          [sec.id, s.texts['sec_full_' + sec.id], s.texts['sec_find_' + sec.id], s.texts['sec_imp_' + sec.id]]);
      }
    });
  }
  console.log(`done: ${ok} fully scrubbed, ${degraded} pattern-only (scrubbed_at left null — will retry on next final save/export).`);
  await db.pool.end();
}

main().catch(e => { console.error(e.message); process.exit(1); });
