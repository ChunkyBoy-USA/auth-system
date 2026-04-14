const initSqlJs = require('sql.js');
const path = require('path');
const fs = require('fs');

const DATA_DIR = path.join(__dirname, '..', '..', 'data');
const DB_PATH = path.join(DATA_DIR, 'auth.db');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

let db = null;

// ─── Persist DB to disk ──────────────────────────────────────────
function persist() {
  if (!db) return;
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

// ─── Initialize / load DB ────────────────────────────────────────
async function initDb() {
  const SQL = await initSqlJs();

  let data = null;
  if (fs.existsSync(DB_PATH)) {
    data = fs.readFileSync(DB_PATH);
  }

  db = new SQL.Database(data ? new Uint8Array(data) : undefined);

  db.run('PRAGMA foreign_keys = ON');

  db.run(`
    CREATE TABLE IF NOT EXISTS subjects (
      id INTEGER PRIMARY KEY,
      type TEXT NOT NULL CHECK(type IN ('member', 'community_staff', 'platform_staff')),
      name TEXT NOT NULL
    );
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      subject_id INTEGER NOT NULL REFERENCES subjects(id),
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT,
      otp_secret TEXT,
      passkey_credential_id TEXT,
      passkey_public_key TEXT,
      created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
    );
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      device_name TEXT,
      ip_address TEXT,
      created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
      expires_at INTEGER NOT NULL,
      last_active_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
    );
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS temp_tokens (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      type TEXT NOT NULL,
      created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
      expires_at INTEGER NOT NULL
    );
  `);

  const subjectTypes = [
    [1, 'member', 'Member'],
    [2, 'community_staff', 'Community Staff'],
    [3, 'platform_staff', 'Platform Staff'],
  ];
  for (const [id, type, name] of subjectTypes) {
    db.run('INSERT OR IGNORE INTO subjects (id, type, name) VALUES (?, ?, ?)', [id, type, name]);
  }

  persist();
  return db;
}

// ─── Sync prepare() — mirrors better-sqlite3 API ──────────────────
function prepare(sql) {
  return {
    run(...args) {
      db.run(sql, args);
      persist();
      const lastId = db.exec('SELECT last_insert_rowid()');
      return {
        lastInsertRowid: lastId[0]?.values[0][0] ?? 0,
        changes: db.getRowsModified(),
      };
    },
    get(...args) {
      const stmt = db.prepare(sql);
      stmt.bind(args);
      if (stmt.step()) {
        const row = stmt.getAsObject();
        stmt.free();
        return row;
      }
      stmt.free();
      return undefined;
    },
    all(...args) {
      const stmt = db.prepare(sql);
      stmt.bind(args);
      const rows = [];
      while (stmt.step()) rows.push(stmt.getAsObject());
      stmt.free();
      return rows;
    },
  };
}

module.exports = { initDb, prepare };
