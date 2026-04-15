const express = require('express');
const {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} = require('@simplewebauthn/server');
const { isoBase64URL, isoUint8Array } = require('@simplewebauthn/server/helpers');
const { findUserByUsername, findUserById, updateUserPasskey, createSession, getSubjectById } = require('../db/models');
const { authMiddleware } = require('../middleware/auth');
const { parseDevice } = require('./passkey-helpers');

const router = express.Router();

// In-memory store for WebAuthn challenges (cleared on use/expiry)
const challengeStore = new Map();

// ─── POST /api/auth/passkey/register-options ───────────────────
router.post('/register-options', authMiddleware, async (req, res) => {
  const user = req.user;

  // Promise.resolve() forces the thenable (v9.0.3) into a real Promise
  const options = await Promise.resolve(generateRegistrationOptions({
    rpName: 'AuthSystem',
    rpID: 'localhost',
    userName: user.username,
    userID: isoUint8Array.fromUTF8String(String(user.id)),
    timeout: 60000,
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
  }));

  // Convert user.id from Uint8Array to base64url string so it serialises
  // correctly in JSON (Uint8Array serialises as { "0": 49 } which
  // startRegistration cannot decode)
  options.user = {
    ...options.user,
    id: isoBase64URL.fromBuffer(options.user.id),
  };

  // Store challenge in base64url form for consistent comparison at verify time
  challengeStore.set(user.id, {
    challenge: options.challenge,
    expiresAt: Date.now() + 5 * 60 * 1000,
  });

  res.json(options);
});

// ─── POST /api/auth/passkey/register-verify ─────────────────────
router.post('/register-verify', authMiddleware, async (req, res) => {
  const { body } = req;
  const user = req.user;

  // Guard: require a body with a credential ID to reach the challenge check
  if (!body || !body.id) {
    return res.status(400).json({ error: 'Challenge expired or not found. Please try again.' });
  }

  const stored = challengeStore.get(user.id);
  if (!stored || stored.expiresAt < Date.now()) {
    return res.status(400).json({ error: 'Challenge expired or not found. Please try again.' });
  }

  try {
    const verification = await verifyRegistrationResponse({
      response: body,
      expectedChallenge: stored.challenge,
      expectedOrigin: 'http://localhost:3000',
      expectedRPID: 'localhost',
    });

    const { credentialID, credentialPublicKey } = verification.registrationInfo;

    updateUserPasskey(
      user.id,
      isoBase64URL.fromBuffer(credentialID),
      isoBase64URL.fromBuffer(credentialPublicKey)
    );

    challengeStore.delete(user.id);
    res.json({ success: true, message: 'Passkey registered successfully' });
  } catch (err) {
    res.status(400).json({ error: 'Passkey registration failed: ' + err.message });
  }
});

// ─── POST /api/auth/passkey/login-options ───────────────────────
router.post('/login-options', async (req, res) => {
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ error: 'username is required' });
  }

  const user = findUserByUsername(username);
  if (!user || !user.passkey_credential_id) {
    return res.status(404).json({ error: 'No passkey found for this user' });
  }

  const options = await Promise.resolve(generateAuthenticationOptions({
    rpID: 'localhost',
    allowCredentials: [
      {
        id: user.passkey_credential_id,
        type: 'public-key',
      },
    ],
    userVerification: 'preferred',
    timeout: 60000,
  }));

  // Store challenge for verification
  challengeStore.set(`auth:${user.id}`, {
    challenge: options.challenge,
    userId: user.id,
    expiresAt: Date.now() + 5 * 60 * 1000,
  });

  res.json(options);
});

// ─── POST /api/auth/passkey/login-verify ───────────────────────
router.post('/login-verify', async (req, res) => {
  const { body } = req;
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ error: 'username is required' });
  }

  const user = findUserByUsername(username);
  if (!user || !user.passkey_credential_id) {
    return res.status(404).json({ error: 'User or passkey not found' });
  }

  const stored = challengeStore.get(`auth:${user.id}`);
  if (!stored || stored.expiresAt < Date.now()) {
    return res.status(400).json({ error: 'Challenge expired or not found. Please try again.' });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response: body,
      expectedChallenge: stored.challenge,
      expectedOrigin: 'http://localhost:3000',
      expectedRPID: 'localhost',
      authenticator: {
        credentialID: user.passkey_credential_id,
        credentialPublicKey: isoBase64URL.toBuffer(user.passkey_public_key),
      },
    });

    challengeStore.delete(`auth:${user.id}`);

    // Create session
    const session = createSession({
      id: require('uuid').v4(),
      userId: user.id,
      ...parseDevice(req),
      expiresAt: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60,
    });

    const subject = getSubjectById(user.subject_id);
    res.json({
      success: true,
      token: session.id,
      user: { id: user.id, username: user.username, subjectType: subject.type },
    });
  } catch (err) {
    res.status(400).json({ error: 'Passkey verification failed: ' + err.message });
  }
});

module.exports = router;
