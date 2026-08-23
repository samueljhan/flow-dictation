#!/usr/bin/env node
// One-time migration: replace timestamp-derived report ids (yyyymmddhhmm[-n])
// with random "R-XXXXXX" ids, everywhere they are referenced, in ONE
// transaction. Also adds reports.scrubbed_at and nulls study_id_label on every
// report that already has a final (those are done; drafts keep theirs).
//
// Usage (cloud-sql-proxy running, PG* vars set):
//   node scripts/migrate-random-ids.js --dry-run   # show what would change
//   node scripts/migrate-random-ids.js             # do it
require('dotenv').config();
const crypto = require('crypto');
const db = require('../db');

const DRY = process.argv.includes('--dry-run');
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';   // 32 chars: no 0/O/1/I

function randomReportId() {
  // 256 % 32 === 0, so a byte modulo 32 is unbiased
  return 'R-' + [...crypto.randomBytes(6)].map(b => ALPHABET[b % 32]).join('');
}

async function main() {
  const rows = await db.many(`select id from reports order by created_at`);
  const olds = rows.map(r => r.id).filter(id => !/^R-[A-Z2-9]{6}$/.test(id));
  console.log(`${rows.length} reports; ${olds.length} with non-random ids to migrate.`);

  // Build the map in JS so uniqueness (against new ids AND untouched ids) is certain
  const used = new Set(rows.map(r => r.id));
  const map = new Map();
  for (const old of olds) {
    let id;
    do { id = randomReportId(); } while (used.has(id));
    used.add(id);
    map.set(old, id);
  }

  if (DRY) {
    for (const [o, n] of map) console.log(`  ${o} -> ${n}`);
    console.log('Dry run — nothing written.');
    await db.pool.end();
    return;
  }

  await db.tx(async client => {
    // Additive column for the scrub layer (idempotent)
    await client.query(`alter table reports add column if not exists scrubbed_at timestamptz`);

    // FKs on report_sections/report_revisions have no ON UPDATE CASCADE, so
    // drop them for the duration of the id rewrite and restore them after.
    await client.query(`alter table report_sections drop constraint report_sections_report_id_fkey`);
    await client.query(`alter table report_revisions drop constraint report_revisions_report_id_fkey`);

    for (const [old, id] of map) {
      await client.query(`update reports set id = $2 where id = $1`, [old, id]);
      await client.query(`update report_sections set report_id = $2 where report_id = $1`, [old, id]);
      await client.query(`update report_revisions set report_id = $2 where report_id = $1`, [old, id]);
    }

    await client.query(
      `alter table report_sections add constraint report_sections_report_id_fkey
       foreign key (report_id) references reports(id) on delete cascade`);
    await client.query(
      `alter table report_revisions add constraint report_revisions_report_id_fkey
       foreign key (report_id) references reports(id) on delete cascade`);

    // Ephemeral study IDs: anything already finalized loses its label now
    const { rowCount } = await client.query(
      `update reports set study_id_label = null where final_text is not null and study_id_label is not null`);
    console.log(`study_id_label nulled on ${rowCount} finalized reports.`);
  });

  // Post-checks: counts, FK integrity, and that every id is now random-format
  const [reports, sections, revisions, orphans, badIds] = await Promise.all([
    db.one(`select count(*)::int n from reports`),
    db.one(`select count(*)::int n from report_sections`),
    db.one(`select count(*)::int n from report_revisions`),
    db.one(`select (select count(*) from report_sections s where not exists (select 1 from reports r where r.id = s.report_id))::int
            + (select count(*) from report_revisions v where not exists (select 1 from reports r where r.id = v.report_id))::int as n`),
    db.one(`select count(*)::int n from reports where id !~ '^R-[A-Z2-9]{6}$'`)
  ]);
  console.log(`after: reports=${reports.n} sections=${sections.n} revisions=${revisions.n} orphans=${orphans.n} non_random_ids=${badIds.n}`);
  if (orphans.n || badIds.n) process.exitCode = 1;
  await db.pool.end();
}

main().catch(e => { console.error(e.message); process.exit(1); });
