/**
 * Auth routes — Delegated entirely to AuthService.
 *
 * The route handlers are now thin shims: they extract request data,
 * call AuthService, and format the HTTP response. All business logic
 * lives in AuthService and its registered Authenticators.
 *
 * Adding a new login method:
 *   1. Create src/auth/<Method>Authenticator.js
 *   2. Register it on authService in server.js
 *   3. Add a POST /api/auth/login/<method> route here
 *   No changes to AuthService needed.
 */

const express = require('express');
const { authService, TokenError, AuthError } = require('../auth/AuthService');
const { authMiddleware } = require('../middleware/auth');
const { policyForUser } = require('../auth/SubjectPolicy');

const router = express.Router();

// ─── POST /api/auth/register ────────────────────────────────────────────────
router.post('/register', async (req, res) => {
  const { username, password, subjectId } = req.body;
  if (!username || !password || !subjectId) {
    return res.status(400).json({ error: 'username, password, subjectId are required' });
  }

  try {
    const { user, subject } = await authService.registerUser({ username, password, subjectId });
    res.json({ success: true, user: { id: user.id, username: user.username, subjectType: subject.type } });
  } catch (err) {
    const status = err.message === 'Username already taken' ? 409 : 400;
    res.status(status).json({ error: err.message });
  }
});

// ─── POST /api/auth/login/password ──────────────────────────────────────────
router.post('/login/password', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }

  try {
    const result = await authService.login('password', { username, password }, req);
    return res.json(result);
  } catch (err) {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// ─── POST /api/auth/login/otp ───────────────────────────────────────────────
router.post('/login/otp', async (req, res) => {
  const { username, otp_code } = req.body;
  if (!username || !otp_code) {
    return res.status(400).json({ error: 'username and otp_code are required' });
  }

  // Check if user exists and has OTP enabled
  const { findUserByUsername } = require('../db/models');
  const user = findUserByUsername(username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  if (!user.otp_secret) {
    return res.status(400).json({
      error: 'OTP not set up for this account',
      recovery_url: '/recover.html',
    });
  }

  try {
    const result = await authService.login('otp', { username, otp_code }, req);
    return res.json(result);
  } catch (err) {
    res.status(401).json({ error: 'Invalid OTP code' });
  }
});

// ─── POST /api/auth/mfa/init ────────────────────────────────────────────────
router.post('/mfa/init', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }

  const { findUserByUsername } = require('../db/models');
  const bcrypt = require('bcryptjs');
  const user = findUserByUsername(username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  if (!user.otp_secret) return res.status(400).json({ error: 'User has not set up OTP' });

  // Delegate to AuthService for the MFA flow (reuse _initiateMfaFlow logic)
  try {
    const { v4: uuidv4 } = require('uuid');
    const { createTempToken, getSubjectById } = require('../db/models');
    const now = Math.floor(Date.now() / 1000);
    const tempToken = uuidv4();
    createTempToken({ token: tempToken, userId: user.id, type: 'mfa_init', expiresAt: now + 5 * 60 });
    const subject = getSubjectById(user.subject_id);
    return res.json({
      mfa_pending: true,
      temp_token: tempToken,
      message: 'Password verified. Please enter your OTP code.',
      user: { id: user.id, username: user.username, subjectType: subject.type },
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ─── POST /api/auth/mfa/verify ────────────────────────────────────────────
router.post('/mfa/verify', (req, res) => {
  const { temp_token, otp_code } = req.body;
  if (!temp_token || !otp_code) {
    return res.status(400).json({ error: 'temp_token and otp_code are required' });
  }

  try {
    const result = authService.mfaVerify({ temp_token, otp_code }, req);
    res.json(result);
  } catch (err) {
    const status = err instanceof TokenError ? 401 : 400;
    res.status(status).json({ error: err.message });
  }
});

// ─── POST /api/auth/logout ─────────────────────────────────────────────────
router.post('/logout', authMiddleware, (req, res) => {
  authService.sessionManager.delete(req.session.id);
  res.json({ success: true });
});

// ─── POST /api/auth/logout-all ──────────────────────────────────────────────
router.post('/logout-all', authMiddleware, (req, res) => {
  authService.sessionManager.deleteAllForUser(req.user.id);
  res.json({ success: true });
});

// ─── GET /api/auth/me ───────────────────────────────────────────────────────
router.get('/me', authMiddleware, (req, res) => {
  res.json(authService.buildMeResponse(req.user));
});

// ─── GET /api/auth/sessions ───────────────────────────────────────────────
router.get('/sessions', authMiddleware, (req, res) => {
  const sessions = authService.sessionManager.listForUser(req.user.id, req.session.id);
  res.json(sessions);
});

// ─── DELETE /api/auth/sessions/:id ────────────────────────────────────────
router.delete('/sessions/:id', authMiddleware, (req, res) => {
  const { id } = req.params;
  const session = authService.sessionManager.findValidSession(id);
  if (!session || session.user_id !== req.user.id) {
    return res.status(404).json({ error: 'Session not found' });
  }
  if (session.id === req.session.id) {
    return res.status(400).json({ error: 'Cannot revoke current session — use /logout instead' });
  }
  authService.sessionManager.delete(id);
  res.json({ success: true });
});

// ─── POST /api/auth/otp/setup ─────────────────────────────────────────────
router.post('/otp/setup', authMiddleware, async (req, res) => {
  try {
    const result = await authService.initiateOtpSetup(req.user);
    return res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ─── POST /api/auth/otp/enable ─────────────────────────────────────────────
router.post('/otp/enable', authMiddleware, (req, res) => {
  const { otp_code, setupToken } = req.body;
  if (!otp_code || !setupToken) {
    return res.status(400).json({ error: 'otp_code and setupToken are required' });
  }

  try {
    authService.confirmOtpSetup(req.user, { otp_code, setupToken });
    res.json({ success: true, message: 'OTP is now enabled' });
  } catch (err) {
    const status = err instanceof TokenError ? 401 : 400;
    res.status(status).json({ error: err.message });
  }
});

// ─── POST /api/auth/otp/disable ───────────────────────────────────────────
router.post('/otp/disable', authMiddleware, (req, res) => {
  const { otp_code } = req.body;
  if (!otp_code) {
    return res.status(400).json({ error: 'otp_code is required' });
  }

  try {
    authService.disableOtp(req.user, { otp_code });
    res.json({ success: true, message: 'OTP has been disabled' });
  } catch (err) {
    // "OTP not enabled" is a business logic error (400); wrong code is an auth failure (401)
    const status = err.message === 'OTP not enabled' ? 400 : 401;
    res.status(status).json({ error: err.message });
  }
});

// ─── POST /api/auth/recover/reset-otp ──────────────────────────────────────
router.post('/recover/reset-otp', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }

  const { findUserByUsername, updateUserOtp } = require('../db/models');
  const user = findUserByUsername(username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const bcrypt = require('bcryptjs');
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  updateUserOtp(user.id, null);
  res.json({
    success: true,
    message: 'OTP has been reset. You can now log in with just your password.',
  });
});

module.exports = router;
