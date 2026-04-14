const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const DATA_DIR = path.join(__dirname, '..', 'data');
const DB_PATH = path.join(DATA_DIR, 'auth.db');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const db = new Database(DB_PATH);

// Enable foreign keys
db.pragma('foreign_keys = ON');

// Initialize schema
db.exec(`
  CREATE TABLE IF NOT EXISTS subjects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL CHECK(type IN ('member', 'community_staff', 'platform_staff')),
    name TEXT NOT NULL
  );

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

  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    device_name TEXT,
    ip_address TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    expires_at INTEGER NOT NULL,
    last_active_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
  );

  CREATE TABLE IF NOT EXISTS temp_tokens (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    type TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    expires_at INTEGER NOT NULL
  );
`);

// Seed subjects if not exist
const insertSubject = db.prepare(
  'INSERT OR IGNORE INTO subjects (id, type, name) VALUES (?, ?, ?)'
);
const subjectTypes = [
  [1, 'member', 'Member'],
  [2, 'community_staff', 'Community Staff'],
  [3, 'platform_staff', 'Platform Staff'],
];
const seedSubjects = db.transaction(() => {
  for (const [id, type, name] of subjectTypes) {
    insertSubject.run(id, type, name);
  }
});
seedSubjects();

module.exports = db;
