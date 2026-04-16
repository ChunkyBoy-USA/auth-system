const express = require('express');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const {
  findUserByUsername,
  findUserById,
  createUser,
  createSession,
  findSessionById,
  deleteSession,
  deleteAllSessionsForUser,
  touchSession,
  createTempToken,
  findTempToken,
  deleteTempToken,
  findSessionsByUserId,
  updateUserOtp,
  updateUserPasskey,
  getSubjectById,
} = require('../db/models');
const { authMiddleware } = require('../middleware/auth');

const router = express.Router();

// ─── Helpers ───────────────────────────────────────────────────
function parseDevice(req) {
  const ua = req.headers['user-agent'] || 'Unknown Device';
  // Extract a short device name from User-Agent
  let deviceName = 'Unknown Device';
  if (ua.includes('Edg/')) deviceName = 'Edge';
  else if (ua.includes('Chrome')) deviceName = 'Chrome';
  else if (ua.includes('Firefox')) deviceName = 'Firefox';
  else if (ua.includes('Safari') && !ua.includes('Chrome')) deviceName = 'Safari';
  else if (ua.includes('Postman')) deviceName = 'Postman';
  else deviceName = ua.slice(0, 40);
  return { deviceName, ipAddress: req.ip || req.connection.remoteAddress || '0.0.0.0' };
}

function makeSession(user, req) {
  const { deviceName, ipAddress } = parseDevice(req);
  const now = Math.floor(Date.now() / 1000);
  return createSession({
    id: uuidv4(),
    userId: user.id,
    deviceName,
    ipAddress,
    expiresAt: now + 7 * 24 * 60 * 60, // 7 days
  });
}

// ─── POST /api/auth/register ───────────────────────────────────
router.post('/register', async (req, res) => {
  const { username, password, subjectId } = req.body;

  if (!username || !password || !subjectId) {
    return res.status(400).json({ error: 'username, password, subjectId are required' });
  }

  const subject = getSubjectById(subjectId);
  if (!subject) {
    return res.status(400).json({ error: 'Invalid subjectId' });
  }

  const existing = findUserByUsername(username);
  if (existing) {
    return res.status(409).json({ error: 'Username already taken' });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const user = createUser({ username, passwordHash, subjectId });

  res.json({ success: true, user: { id: user.id, username: user.username, subjectType: subject.type } });
});

// ─── POST /api/auth/login/password ──────────────────────────────
router.post('/login/password', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }

  const user = findUserByUsername(username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // If user has OTP enabled, initiate MFA flow instead
  if (user.otp_secret) {
    const now = Math.floor(Date.now() / 1000);
    const tempToken = uuidv4();
    createTempToken({
      token: tempToken,
      userId: user.id,
      type: 'mfa_init',
      expiresAt: now + 5 * 60, // 5 min TTL
    });
    return res.json({
      mfa_pending: true,
      temp_token: tempToken,
      message: 'Password verified. Please enter your OTP code.',
    });
  }

  const session = makeSession(user, req);
  const subject = getSubjectById(user.subject_id);
  res.json({
    success: true,
    token: session.id,
    user: { id: user.id, username: user.username, subjectType: subject.type },
  });
});

// ─── POST /api/auth/login/otp ───────────────────────────────────
router.post('/login/otp', (req, res) => {
  const { username, otp_code } = req.body;

  if (!username || !otp_code) {
    return res.status(400).json({ error: 'username and otp_code are required' });
  }

  const user = findUserByUsername(username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  if (!user.otp_secret) {
    return res.status(400).json({
      error: 'OTP not set up for this account. Use password login or visit /recover to reset OTP.',
      recovery_url: '/recover.html',
    });
  }

  const verified = speakeasy.totp.verify({ secret: user.otp_secret, encoding: 'base32', token: otp_code });
  if (!verified) {
    return res.status(401).json({ error: 'Invalid OTP code' });
  }

  const session = makeSession(user, req);
  const subject = getSubjectById(user.subject_id);
  res.json({
    success: true,
    token: session.id,
    user: { id: user.id, username: user.username, subjectType: subject.type },
  });
});

// ─── POST /api/auth/mfa/init ────────────────────────────────────
router.post('/mfa/init', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }

  const user = findUserByUsername(username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  if (!user.otp_secret) {
    return res.status(400).json({ error: 'User has not set up OTP' });
  }

  const now = Math.floor(Date.now() / 1000);
  const tempToken = uuidv4();
  createTempToken({
    token: tempToken,
    userId: user.id,
    type: 'mfa_init',
    expiresAt: now + 5 * 60,
  });

  res.json({
    mfa_pending: true,
    temp_token: tempToken,
    message: 'Password verified. Please enter your OTP code.',
  });
});

// ─── POST /api/auth/mfa/verify ──────────────────────────────────
router.post('/mfa/verify', (req, res) => {
  const { temp_token, otp_code } = req.body;

  if (!temp_token || !otp_code) {
    return res.status(400).json({ error: 'temp_token and otp_code are required' });
  }

  const now = Math.floor(Date.now() / 1000);
  const temp = findTempToken(temp_token);

  if (!temp || temp.expires_at < now) {
    return res.status(401).json({ error: 'Temp token expired or invalid' });
  }

  const user = findUserById(temp.user_id);
  if (!user || !user.otp_secret) {
    return res.status(401).json({ error: 'User not found or OTP not set up' });
  }

  const verified = speakeasy.totp.verify({ secret: user.otp_secret, encoding: 'base32', token: otp_code });
  if (!verified) {
    return res.status(401).json({ error: 'Invalid OTP code' });
  }

  // Clean up temp token
  deleteTempToken(temp_token);

  // Create real session
  const session = makeSession(user, req);
  const subject = getSubjectById(user.subject_id);

  res.json({
    success: true,
    token: session.id,
    user: { id: user.id, username: user.username, subjectType: subject.type },
  });
});

// ─── POST /api/auth/logout ──────────────────────────────────────
router.post('/logout', authMiddleware, (req, res) => {
  deleteSession(req.session.id);
  res.json({ success: true });
});

// ─── POST /api/auth/logout-all ──────────────────────────────────
router.post('/logout-all', authMiddleware, (req, res) => {
  deleteAllSessionsForUser(req.user.id);
  res.json({ success: true });
});

// ─── GET /api/auth/me ───────────────────────────────────────────
router.get('/me', authMiddleware, (req, res) => {
  const subject = getSubjectById(req.user.subject_id);
  res.json({
    id: req.user.id,
    username: req.user.username,
    subjectType: subject.type,
    hasOtp: !!req.user.otp_secret,
    hasPasskey: !!req.user.passkey_credential_id,
    createdAt: req.user.created_at,
  });
});

// ─── GET /api/auth/sessions ────────────────────────────────────
router.get('/sessions', authMiddleware, (req, res) => {
  const sessions = findSessionsByUserId(req.user.id);
  const now = Math.floor(Date.now() / 1000);
  res.json(
    sessions.map((s) => ({
      id: s.id,
      deviceName: s.device_name,
      ipAddress: s.ip_address,
      createdAt: s.created_at,
      expiresAt: s.expires_at,
      lastActiveAt: s.last_active_at,
      isCurrent: s.id === req.session.id,
      isExpired: s.expires_at < now,
    }))
  );
});

// ─── DELETE /api/auth/sessions/:id ─────────────────────────────
router.delete('/sessions/:id', authMiddleware, (req, res) => {
  const { id } = req.params;
  const session = findSessionById(id);
  if (!session || session.user_id !== req.user.id) {
    return res.status(404).json({ error: 'Session not found' });
  }
  if (session.id === req.session.id) {
    return res.status(400).json({ error: 'Cannot revoke current session — use /logout instead' });
  }
  deleteSession(id);
  res.json({ success: true });
});

// ─── POST /api/auth/otp/setup ────────────────────────────────────
router.post('/otp/setup', authMiddleware, async (req, res) => {
  if (req.user.otp_secret) {
    return res.status(400).json({ error: 'OTP already set up' });
  }

  const secret = speakeasy.generateSecret({ name: req.user.username, issuer: 'AuthSystem', length: 20 });

  // Store the pending secret in temp_tokens instead of immediately saving to user record
  const now = Math.floor(Date.now() / 1000);
  const setupToken = uuidv4();
  createTempToken({
    token: setupToken,
    userId: req.user.id,
    type: 'otp_setup_pending',
    expiresAt: now + 10 * 60, // 10 min TTL for setup
    data: secret.base32, // Store the secret here temporarily
  });

  const qrCodeDataUrl = await QRCode.toDataURL(secret.otpauth_url);

  res.json({
    secret: secret.base32,
    otpauthUri: secret.otpauth_url,
    qrCodeDataUrl,
    setupToken,
    message: 'Scan this secret in your authenticator app. Then enable with /api/auth/otp/enable',
  });
});

// ─── POST /api/auth/otp/enable ───────────────────────────────────
router.post('/otp/enable', authMiddleware, (req, res) => {
  const { otp_code, setupToken } = req.body;

  if (!otp_code || !setupToken) {
    return res.status(400).json({ error: 'otp_code and setupToken are required' });
  }

  if (req.user.otp_secret) {
    return res.status(400).json({ error: 'OTP already enabled' });
  }

  // Retrieve the pending secret from temp_tokens
  const now = Math.floor(Date.now() / 1000);
  const temp = findTempToken(setupToken);

  if (!temp || temp.expires_at < now || temp.type !== 'otp_setup_pending' || temp.user_id !== req.user.id) {
    return res.status(401).json({ error: 'Setup token expired or invalid. Call /otp/setup again.' });
  }

  const pendingSecret = temp.data;
  if (!pendingSecret) {
    return res.status(500).json({ error: 'Setup token missing secret data' });
  }

  // Verify the OTP code against the pending secret
  const verified = speakeasy.totp.verify({ secret: pendingSecret, encoding: 'base32', token: otp_code });
  if (!verified) {
    return res.status(401).json({ error: 'Invalid OTP code — setup not confirmed' });
  }

  // Verification successful — save the secret to the user record
  updateUserOtp(req.user.id, pendingSecret);
  deleteTempToken(setupToken);

  res.json({ success: true, message: 'OTP is now enabled' });
});

// ─── POST /api/auth/otp/disable ─────────────────────────────────
router.post('/otp/disable', authMiddleware, (req, res) => {
  const { otp_code } = req.body;

  if (!otp_code) {
    return res.status(400).json({ error: 'otp_code is required' });
  }

  if (!req.user.otp_secret) {
    return res.status(400).json({ error: 'OTP not enabled' });
  }

  const verified = speakeasy.totp.verify({ secret: req.user.otp_secret, encoding: 'base32', token: otp_code });
  if (!verified) {
    return res.status(401).json({ error: 'Invalid OTP code' });
  }

  updateUserOtp(req.user.id, null);
  res.json({ success: true, message: 'OTP has been disabled' });
});

// ─── POST /api/auth/recover/reset-otp ────────────────────────────
// Allows a user to reset their OTP by providing username + password.
// This lets users who enabled OTP but failed setup to regain access.
router.post('/recover/reset-otp', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }

  const user = findUserByUsername(username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Clear any OTP secret so user can log in normally
  updateUserOtp(user.id, null);
  res.json({
    success: true,
    message: 'OTP has been reset. You can now log in with just your password.',
  });
});

module.exports = router;
