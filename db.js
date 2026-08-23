// Postgres access for Flow Dictation — one Pool, parameterized SQL, no query
// builder. Replaces the Supabase client; every caller goes through query().
//
// Connection, by environment:
//   Cloud Run  — INSTANCE_CONNECTION_NAME is set; connect over the Cloud SQL
//                Unix socket at /cloudsql/<instance> (mounted by
//                --add-cloudsql-instances). PGUSER/PGPASSWORD/PGDATABASE still
//                name the user, password (Secret Manager), and database.
//   Local      — standard PG* variables (PGHOST/PGPORT/PGUSER/PGPASSWORD/
//                PGDATABASE), pointed at a cloud-sql-proxy on 127.0.0.1.
//                node-postgres reads them itself, so nothing is passed here.
const { Pool, types } = require('pg');

// bigint identity ids (assist_messages, report_sections, report_revisions)
// come back as JS numbers, as they did from Supabase; they are far below 2^53.
types.setTypeParser(types.builtins.INT8, v => (v === null ? null : Number(v)));

const INSTANCE = process.env.INSTANCE_CONNECTION_NAME;
const SOCKET_DIR = process.env.DB_SOCKET_DIR || '/cloudsql';

// Cloud SQL via Unix socket — host is the socket directory, not a hostname.
// Locally the PG* variables carry everything, so config stays empty.
const config = INSTANCE
  ? {
      host: `${SOCKET_DIR}/${INSTANCE}`,
      user: process.env.PGUSER,
      password: process.env.PGPASSWORD,
      database: process.env.PGDATABASE
    }
  : {};

// Cloud Run scales to zero and a db-g1-small has few connections to spare —
// keep the pool small; the app is single-user.
const pool = new Pool({ ...config, max: 5, idleTimeoutMillis: 30000 });

const configured = !!(INSTANCE || process.env.PGHOST || process.env.PGDATABASE);

pool.on('error', err => {
  // An idle client dropped by the server; the pool replaces it. Log the
  // message only — never query text or parameters.
  console.error('[db] idle client error:', err.message);
});

async function query(text, params) {
  const res = await pool.query(text, params);
  return res;
}

// All rows
async function many(text, params) {
  return (await query(text, params)).rows;
}

// Exactly one row, or null when nothing matched
async function one(text, params) {
  const rows = (await query(text, params)).rows;
  return rows.length ? rows[0] : null;
}

// Run fn(client) inside a transaction; rolled back on throw
async function tx(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const out = await fn(client);
    await client.query('COMMIT');
    return out;
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch { /* connection already gone */ }
    throw e;
  } finally {
    client.release();
  }
}

// Where the app is connecting, for the startup banner (never the password)
function describe() {
  if (INSTANCE) return `cloud-sql socket ${SOCKET_DIR}/${INSTANCE} db=${process.env.PGDATABASE} user=${process.env.PGUSER}`;
  return `tcp ${process.env.PGHOST || 'localhost'}:${process.env.PGPORT || 5432} db=${process.env.PGDATABASE || '(default)'} user=${process.env.PGUSER || '(default)'}`;
}

module.exports = { pool, query, many, one, tx, configured, describe };
