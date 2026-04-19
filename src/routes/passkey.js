/**
 * Passkey routes — Delegated to AuthService and ChallengeStore.
 *
 * Previously contained duplicated session creation logic and an unmanaged
 * in-memory challenge store. Now uses:
 *   - SessionManager (from AuthService.sessionManager) for session creation
 *   - ChallengeStore for WebAuthn challenge lifecycle + background cleanup
 *   - AuthService.buildLoginResponse() for consistent response formatting
 */

const express = require('express');
const {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} = require('@simplewebauthn/server');
const { isoBase64URL, isoUint8Array } = require('@simplewebauthn/server/helpers');
const { findUserByUsername, findUserById, updateUserPasskey, getSubjectById } = require('../db/models');
const { authMiddleware } = require('../middleware/auth');
const { authService } = require('../auth/AuthService');
const { challengeStore } = require('../auth/ChallengeStore');
const { parseDevice } = require('../auth/SessionManager');

const router = express.Router();

// ─── RP configuration helpers ──────────────────────────────────────────────

function getRpId(req) {
  const rpId = process.env.WEBAUTHN_RP_ID;
  if (rpId) return rpId;
  const origin = req.get('origin') || req.headers.origin;
  if (origin) {
    try { return new URL(origin).hostname; } catch {}
  }
  return 'localhost';
}

function getRpOrigin(req) {
  const origin = req.get('origin') || req.headers.origin;
  if (origin) {
    try { const url = new URL(origin); return `${url.protocol}//${url.host}`; } catch {}
  }
  const port = process.env.PORT || 3000;
  return `http://localhost:${port}`;
}

// ─── POST /api/auth/passkey/register-options ─────────────────────────────
router.post('/register-options', authMiddleware, async (req, res) => {
  const user = req.user;
  const rpId = getRpId(req);
  const rpOrigin = getRpOrigin(req);

  const options = await Promise.resolve(generateRegistrationOptions({
    rpName: 'AuthSystem',
    rpID: rpId,
    userName: user.username,
    userID: isoUint8Array.fromUTF8String(String(user.id)),
    timeout: 60000,
    authenticatorSelection: {
      residentKey: 'required',
      userVerification: 'preferred',
    },
  }));

  // Serialize user.id as base64url (Uint8Array serialises badly in JSON)
  options.user = { ...options.user, id: isoBase64URL.fromBuffer(options.user.id) };

  // Store challenge in the managed ChallengeStore (auto-expires after 5 min)
  challengeStore.setRegistrationChallenge(user.id, options.challenge);

  res.json(options);
});

// ─── POST /api/auth/passkey/register-verify ────────────────────────────────
router.post('/register-verify', authMiddleware, async (req, res) => {
  const { body } = req;
  if (!body || !body.id) {
    return res.status(400).json({ error: 'Challenge expired or not found. Please try again.' });
  }

  const stored = challengeStore.popRegistrationChallenge(req.user.id);
  if (!stored) {
    return res.status(400).json({ error: 'Challenge expired or not found. Please try again.' });
  }

  try {
    const rpOrigin = getRpOrigin(req);
    const rpId = getRpId(req);

    const verification = await verifyRegistrationResponse({
      response: body,
      expectedChallenge: stored.challenge,
      expectedOrigin: rpOrigin,
      expectedRPID: rpId,
    });

    // Handle v9/v9+ API shape differences
    let credentialId, credentialPublicKey;
    if (verification.registrationInfo?.credential) {
      credentialId = verification.registrationInfo.credential.id;
      credentialPublicKey = verification.registrationInfo.credential.publicKey;
    } else if (verification.registrationInfo?.credentialID) {
      credentialId = isoBase64URL.fromBuffer(verification.registrationInfo.credentialID);
      credentialPublicKey = verification.registrationInfo.credentialPublicKey;
    } else {
      throw new Error('Unexpected credential format from verifyRegistrationResponse');
    }

    updateUserPasskey(
      req.user.id,
      credentialId,
      isoBase64URL.fromBuffer(credentialPublicKey)
    );

    res.json({ success: true, message: 'Passkey registered successfully' });
  } catch (err) {
    res.status(400).json({ error: 'Passkey registration failed: ' + err.message });
  }
});

// ─── POST /api/auth/passkey/login-options ────────────────────────────────
router.post('/login-options', async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'username is required' });

  const user = findUserByUsername(username);
  if (!user || !user.passkey_credential_id) {
    return res.status(404).json({ error: 'No passkey found for this user' });
  }

  const options = await Promise.resolve(generateAuthenticationOptions({
    rpID: getRpId(req),
    allowCredentials: [{
      id: isoBase64URL.toBuffer(user.passkey_credential_id),
      type: 'public-key',
      transports: ['internal', 'hybrid'],
    }],
    userVerification: 'preferred',
    timeout: 60000,
  }));

  challengeStore.setAuthenticationChallenge(user.id, options.challenge);

  res.json(options);
});

// ─── POST /api/auth/passkey/login-verify ─────────────────────────────────
router.post('/login-verify', async (req, res) => {
  const { username, body } = req.body;
  if (!username) return res.status(400).json({ error: 'username is required' });

  const user = findUserByUsername(username);
  if (!user || !user.passkey_credential_id) {
    return res.status(404).json({ error: 'User or passkey not found' });
  }

  if (!body || !body.id) {
    return res.status(400).json({ error: 'Missing credential ID' });
  }

  const stored = challengeStore.popAuthenticationChallenge(user.id);
  if (!stored) {
    return res.status(400).json({ error: 'Challenge expired or not found. Please try again.' });
  }

  try {
    const rpOrigin = getRpOrigin(req);
    const rpId = getRpId(req);

    const verification = await verifyAuthenticationResponse({
      response: body,
      expectedChallenge: stored.challenge,
      expectedOrigin: rpOrigin,
      expectedRPID: rpId,
      authenticator: {
        credentialID: isoBase64URL.toBuffer(user.passkey_credential_id),
        credentialPublicKey: isoBase64URL.toBuffer(user.passkey_public_key),
      },
    });

    // Session creation now goes through SessionManager (consistent with all other auth methods)
    const session = authService.sessionManager.createSession(user, req);
    const loginResponse = authService._buildLoginResponse(user, session);
    res.json(loginResponse);
  } catch (err) {
    res.status(400).json({ error: 'Passkey verification failed: ' + err.message });
  }
});

module.exports = router;
