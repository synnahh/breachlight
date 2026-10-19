import fs from 'node:fs';
import path from 'node:path';
import { config } from './config.js';

// Resolve the built-in module directly from the running Node process. Avoids
// bundler/test-runner resolution quirks with the `node:sqlite` specifier.
const { DatabaseSync } = process.getBuiltinModule('node:sqlite') as typeof import('node:sqlite');

fs.mkdirSync(path.dirname(config.databaseFile), { recursive: true });

const raw = new DatabaseSync(config.databaseFile);
raw.exec('PRAGMA journal_mode = WAL;');
raw.exec('PRAGMA foreign_keys = ON;');

type Param = null | number | bigint | string | Uint8Array;
type Bindings = Param | Record<string, Param>;

interface Stmt {
  run(...params: Bindings[]): { changes: number | bigint; lastInsertRowid: number | bigint };
  get<T = Record<string, unknown>>(...params: Bindings[]): T | undefined;
  all<T = Record<string, unknown>>(...params: Bindings[]): T[];
}

export const db = {
  exec: (sql: string) => raw.exec(sql),
  prepare(sql: string): Stmt {
    const stmt = raw.prepare(sql);
    stmt.setAllowUnknownNamedParameters(true);
    return {
      run: (...p) => stmt.run(...(p as never[])),
      get: <T,>(...p: Bindings[]) => stmt.get(...(p as never[])) as T | undefined,
      all: <T,>(...p: Bindings[]) => stmt.all(...(p as never[])) as T[],
    };
  },
};

// ── One-time migration from the V1 schema ────────────────────────────────
// V1 (built the same day) had a leaner `findings` table. There is no data
// worth preserving across that boundary, so if a V1-shaped table is found we
// drop the old tables and rebuild. A note is printed so the user knows.
try {
  const cols = raw
    .prepare(`SELECT name FROM pragma_table_info('findings')`)
    .all() as Array<{ name: string }>;
  if (cols.length > 0 && !cols.some((c) => c.name === 'service')) {
    console.warn(
      JSON.stringify({
        ts: new Date().toISOString(),
        level: 'warn',
        msg: 'Rebuilding local database for V2 schema (previous V1 findings discarded)',
      }),
    );
    raw.exec(
      'DROP TABLE IF EXISTS actions; DROP TABLE IF EXISTS findings; DROP TABLE IF EXISTS scans;',
    );
  }
  // `emails` is preserved across the V1→V2 boundary; add the new column if missing.
  const emailCols = raw
    .prepare(`SELECT name FROM pragma_table_info('emails')`)
    .all() as Array<{ name: string }>;
  if (emailCols.length > 0 && !emailCols.some((c) => c.name === 'label')) {
    raw.exec('ALTER TABLE emails ADD COLUMN label TEXT');
  }
} catch {
  /* fresh database — nothing to migrate */
}

db.exec(`
CREATE TABLE IF NOT EXISTS emails (
  id              TEXT PRIMARY KEY,
  email           TEXT NOT NULL UNIQUE,
  label           TEXT,
  created_at      TEXT NOT NULL,
  last_scanned_at TEXT
);

CREATE TABLE IF NOT EXISTS scans (
  id               TEXT PRIMARY KEY,
  status           TEXT NOT NULL DEFAULT 'running',
  depth            TEXT NOT NULL,
  options_json     TEXT NOT NULL DEFAULT '{}',
  email_ids_json   TEXT NOT NULL DEFAULT '[]',
  email_addrs_json TEXT NOT NULL DEFAULT '[]',
  started_at       TEXT NOT NULL,
  finished_at      TEXT,
  stages_json      TEXT NOT NULL DEFAULT '[]',
  provider_json    TEXT NOT NULL DEFAULT '[]',
  coverage_json    TEXT NOT NULL DEFAULT '{}',
  summary_json     TEXT,
  comparison_json  TEXT,
  error            TEXT
);

CREATE TABLE IF NOT EXISTS findings (
  id                TEXT PRIMARY KEY,
  scan_id           TEXT,
  email_id          TEXT NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
  service           TEXT NOT NULL,
  breach_name       TEXT NOT NULL,
  title             TEXT NOT NULL,
  domain            TEXT,
  breach_date       TEXT,
  disclosure_date   TEXT,
  first_seen_date   TEXT,
  description       TEXT,
  data_classes      TEXT NOT NULL DEFAULT '[]',
  password_exposed  INTEGER NOT NULL DEFAULT 0,
  email_exposed     INTEGER NOT NULL DEFAULT 0,
  username_exposed  INTEGER NOT NULL DEFAULT 0,
  ip_exposed        INTEGER NOT NULL DEFAULT 0,
  location_exposed  INTEGER NOT NULL DEFAULT 0,
  phone_exposed     INTEGER NOT NULL DEFAULT 0,
  secq_exposed      INTEGER NOT NULL DEFAULT 0,
  financial_exposed INTEGER NOT NULL DEFAULT 0,
  govid_exposed     INTEGER NOT NULL DEFAULT 0,
  sensitive_exposed INTEGER NOT NULL DEFAULT 0,
  password_risk     TEXT,
  severity          TEXT NOT NULL,
  severity_reasons  TEXT NOT NULL DEFAULT '[]',
  why_matters       TEXT NOT NULL DEFAULT '',
  confidence        TEXT NOT NULL DEFAULT 'medium',
  confidence_reason TEXT NOT NULL DEFAULT '',
  association_type  TEXT NOT NULL DEFAULT 'confirmed',
  source            TEXT NOT NULL DEFAULT '',
  provider_ids      TEXT NOT NULL DEFAULT '[]',
  is_demo_data      INTEGER NOT NULL DEFAULT 0,
  pwn_count         INTEGER,
  industry          TEXT,
  status            TEXT NOT NULL DEFAULT 'open',
  discovered_at     TEXT NOT NULL,
  last_seen_at      TEXT NOT NULL,
  UNIQUE (email_id, breach_name)
);

CREATE TABLE IF NOT EXISTS actions (
  id            TEXT PRIMARY KEY,
  finding_id    TEXT REFERENCES findings(id) ON DELETE CASCADE,
  email_id      TEXT REFERENCES emails(id) ON DELETE CASCADE,
  title         TEXT NOT NULL,
  description   TEXT NOT NULL DEFAULT '',
  priority      TEXT NOT NULL DEFAULT 'recommended',
  status        TEXT NOT NULL DEFAULT 'not_started',
  created_at    TEXT NOT NULL,
  completed_at  TEXT,
  dedupe_key    TEXT UNIQUE
);

CREATE TABLE IF NOT EXISTS domain_security (
  domain      TEXT PRIMARY KEY,
  info_json   TEXT NOT NULL,
  checked_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_email ON findings(email_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_actions_finding ON actions(finding_id);
`);

export function setMeta(key: string, value: string): void {
  db.prepare(
    'INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value',
  ).run(key, value);
}
export function getMeta(key: string): string | null {
  return db.prepare('SELECT value FROM meta WHERE key = ?').get<{ value: string }>(key)?.value ?? null;
}

export function setSetting(key: string, value: string): void {
  db.prepare(
    'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value',
  ).run(key, value);
}
export function getSetting(key: string): string | null {
  return db.prepare('SELECT value FROM settings WHERE key = ?').get<{ value: string }>(key)?.value ?? null;
}
export function allSettings(): Record<string, string> {
  const rows = db.prepare('SELECT key, value FROM settings').all<{ key: string; value: string }>();
  return Object.fromEntries(rows.map((r) => [r.key, r.value]));
}
