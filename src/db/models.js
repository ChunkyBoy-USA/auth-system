const { prepare } = require('./database');

// ─── Subject helpers ───────────────────────────────────────────
function getSubjectById(id) {
  return prepare('SELECT * FROM subjects WHERE id = ?').get(id);
}

// ─── User helpers ──────────────────────────────────────────────
function findUserByUsername(username) {
  return prepare('SELECT * FROM users WHERE username = ?').get(username);
}

function findUserById(id) {
  return prepare('SELECT * FROM users WHERE id = ?').get(id);
}

function createUser({ username, passwordHash, subjectId }) {
  prepare(
    'INSERT INTO users (username, password_hash, subject_id) VALUES (?, ?, ?)'
  ).run(username, passwordHash, subjectId);
  // sql.js last_insert_rowid() can be unreliable across statements — query back
  return prepare(
    'SELECT * FROM users WHERE username = ? AND subject_id = ? ORDER BY id DESC LIMIT 1'
  ).get(username, subjectId);
}

function updateUserOtp(userId, otpSecret) {
  prepare('UPDATE users SET otp_secret = ? WHERE id = ?').run(otpSecret, userId);
  return findUserById(userId);
}

function updateUserPasskey(userId, credentialId, publicKey) {
  prepare(
    'UPDATE users SET passkey_credential_id = ?, passkey_public_key = ? WHERE id = ?'
  ).run(credentialId, publicKey, userId);
  return findUserById(userId);
}

// ─── Session helpers ────────────────────────────────────────────
function createSession({ id, userId, deviceName, ipAddress, expiresAt }) {
  prepare(
    'INSERT INTO sessions (id, user_id, device_name, ip_address, expires_at) VALUES (?, ?, ?, ?, ?)'
  ).run(id, userId, deviceName, ipAddress, expiresAt);
  return findSessionById(id);
}

function findSessionById(id) {
  return prepare('SELECT * FROM sessions WHERE id = ?').get(id);
}

function findSessionsByUserId(userId) {
  return prepare('SELECT * FROM sessions WHERE user_id = ? ORDER BY created_at DESC').all(userId);
}

function touchSession(sessionId) {
  prepare("UPDATE sessions SET last_active_at = strftime('%s', 'now') WHERE id = ?").run(sessionId);
}

function deleteSession(sessionId) {
  prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);
}

function deleteAllSessionsForUser(userId) {
  prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
}

// ─── Temp token helpers ─────────────────────────────────────────
function createTempToken({ token, userId, type, expiresAt, data }) {
  prepare(
    'INSERT INTO temp_tokens (token, user_id, type, expires_at, data) VALUES (?, ?, ?, ?, ?)'
  ).run(token, userId, type, expiresAt, data || null);
  return findTempToken(token);
}

function findTempToken(token) {
  return prepare('SELECT * FROM temp_tokens WHERE token = ?').get(token);
}

function deleteTempToken(token) {
  prepare('DELETE FROM temp_tokens WHERE token = ?').run(token);
}

function cleanExpiredTempTokens() {
  const now = Math.floor(Date.now() / 1000);
  prepare('DELETE FROM temp_tokens WHERE expires_at < ?').run(now);
}

module.exports = {
  getSubjectById,
  findUserByUsername,
  findUserById,
  createUser,
  updateUserOtp,
  updateUserPasskey,
  createSession,
  findSessionById,
  findSessionsByUserId,
  touchSession,
  deleteSession,
  deleteAllSessionsForUser,
  createTempToken,
  findTempToken,
  deleteTempToken,
  cleanExpiredTempTokens,
};
