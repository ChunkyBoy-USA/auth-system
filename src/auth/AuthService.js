/**
 * AuthService — Central authentication orchestrator.
 *
 * This is the key abstraction layer that ties everything together.
 * Routes no longer contain login logic — they delegate to AuthService methods.
 * New login methods are added by registering new Authenticator instances;
 * AuthService and the routes never need to change (Open/Closed Principle).
 *
 * Responsibilities:
 *   - Register and invoke authenticators
 *   - Orchestrate MFA flows (password → OTP → session)
 *   - Manage temp tokens for multi-step flows
 *   - Provide a consistent response shape regardless of which authenticator succeeded
 *
 * Example of adding a new login method (OAuth):
 *   const { OAuthAuthenticator } = require('./OAuthAuthenticator');
 *   authService.register(new OAuthAuthenticator());
 *   // No other changes needed anywhere
 */

const { v4: uuidv4 } = require('uuid');
const {
  findUserByUsername,
  findUserById,
  createUser,
  updateUserOtp,
  createTempToken,
  findTempToken,
  deleteTempToken,
  getSubjectById,
} = require('../db/models');
const { SessionManager } = require('./SessionManager');
const { resolvePolicy } = require('./SubjectPolicy');

// Typed errors allow routes to return correct HTTP status codes without
// fragile string matching on error messages.
class AuthError extends Error {
  constructor(message) { super(message); this.name = 'AuthError'; }
}

class TokenError extends AuthError {
  constructor(message) { super(message); this.name = 'TokenError'; }
}

class AuthService {
  constructor() {
    /** @type {Map<string, import('./Authenticator').Authenticator>} */
    this._authenticators = new Map();
    this.sessionManager = new SessionManager();
  }

  // ─── Authenticator registration ────────────────────────────────────────────

  /**
   * Register an authenticator instance. An authenticator with the same
   * type must not be registered twice.
   *
   * @param {import('./Authenticator').Authenticator} authenticator
   */
  register(authenticator) {
    if (this._authenticators.has(authenticator.type)) {
      throw new Error(`Authenticator with type "${authenticator.type}" is already registered`);
    }
    this._authenticators.set(authenticator.type, authenticator);
  }

  /** @returns {import('./Authenticator').Authenticator[]} */
  listAuthenticators() {
    return [...this._authenticators.values()];
  }

  /** @param {string} type @returns {import('./Authenticator').Authenticator|undefined} */
  getAuthenticator(type) {
    return this._authenticators.get(type);
  }

  /**
   * Build a standard context object passed to every authenticator's verify().
   * @returns {{ findUserByUsername, findUserById }}
   */
  _authContext() {
    return { findUserByUsername, findUserById };
  }

  // ─── User management ────────────────────────────────────────────────────────

  /**
   * Register a new user.
   *
   * @param {{ username: string, password: string, subjectId: number }} params
   * @returns {{ user: object, subject: object }}
   */
  async registerUser({ username, password, subjectId }) {
    const subject = getSubjectById(subjectId);
    if (!subject) throw new Error('Invalid subjectId');

    const existing = findUserByUsername(username);
    if (existing) throw new Error('Username already taken');

    const bcrypt = require('bcryptjs');
    const passwordHash = await bcrypt.hash(password, 10);
    const user = createUser({ username, passwordHash, subjectId });
    return { user, subject };
  }

  /**
   * Check whether a user has MFA enabled (OTP secret set).
   * @param {object} user
   * @returns {boolean}
   */
  hasMfaEnabled(user) {
    return !!user.otp_secret;
  }

  // ─── Login flows ────────────────────────────────────────────────────────────

  /**
   * Attempt login using a named authenticator type.
   * Throws on failure; returns a session on success.
   *
   * @param {string} authenticatorType - e.g. 'password', 'otp'
   * @param {object} credentials       - Method-specific credentials
   * @param {object} req               - Express request (for device/IP)
   * @returns {{ token: string, user: object }}
   */
  async login(authenticatorType, credentials, req) {
    const authenticator = this._authenticators.get(authenticatorType);
    if (!authenticator) throw new Error(`Unknown authenticator: ${authenticatorType}`);

    const user = await authenticator.verify(credentials, this._authContext());
    if (!user) throw new Error('Invalid credentials');

    // If MFA is enabled for this user, redirect to MFA flow instead of issuing session
    if (authenticator.requiresMfa && this.hasMfaEnabled(user)) {
      return this._initiateMfaFlow(user, req);
    }

    const session = this.sessionManager.createSession(user, req);
    return this._buildLoginResponse(user, session);
  }

  /**
   * Initiate an MFA flow — creates a temp token and returns mfa_pending.
   *
   * @param {object} user
   * @param {object} req
   * @returns {{ mfa_pending: true, temp_token: string, message: string, user: object }}
   */
  _initiateMfaFlow(user, req) {
    const now = Math.floor(Date.now() / 1000);
    const tempToken = uuidv4();
    createTempToken({
      token: tempToken,
      userId: user.id,
      type: 'mfa_init',
      expiresAt: now + 5 * 60, // 5 minutes
    });
    const subject = getSubjectById(user.subject_id);
    return {
      mfa_pending: true,
      temp_token: tempToken,
      message: 'Password verified. Please enter your OTP code.',
      user: { id: user.id, username: user.username, subjectType: subject.type },
    };
  }

  /**
   * Verify an MFA (OTP) code against a pending temp token.
   * On success, issues a session.
   *
   * @param {{ temp_token: string, otp_code: string }} credentials
   * @param {object} req
   * @returns {{ token: string, user: object }}
   */
  mfaVerify({ temp_token, otp_code }, req) {
    if (!temp_token || !otp_code) throw new AuthError('temp_token and otp_code are required');

    const now = Math.floor(Date.now() / 1000);
    const temp = findTempToken(temp_token);
    if (!temp || temp.expires_at < now) throw new TokenError('Temp token expired or invalid');

    const user = findUserById(temp.user_id);
    if (!user || !user.otp_secret) throw new TokenError('User not found or OTP not set up');

    const otpAuth = this._authenticators.get('otp');
    if (!otpAuth) throw new AuthError('OTP authenticator not registered');

    const verified = otpAuth.verify({ username: user.username, otp_code }, this._authContext());
    if (!verified) throw new TokenError('Invalid OTP code');

    deleteTempToken(temp_token);

    const session = this.sessionManager.createSession(user, req);
    return this._buildLoginResponse(user, session);
  }

  /**
   * Initiate OTP setup (generate secret + QR code).
   *
   * @param {object} user
   * @returns {{ secret: string, otpauthUri: string, qrCodeDataUrl: string, setupToken: string }}
   */
  async initiateOtpSetup(user) {
    if (user.otp_secret) throw new Error('OTP already set up');

    const speakeasy = require('speakeasy');
    const QRCode = require('qrcode');

    const secret = speakeasy.generateSecret({
      name: user.username,
      issuer: 'AuthSystem',
      length: 20,
    });

    const now = Math.floor(Date.now() / 1000);
    const setupToken = uuidv4();
    createTempToken({
      token: setupToken,
      userId: user.id,
      type: 'otp_setup_pending',
      expiresAt: now + 10 * 60, // 10 minutes
      data: secret.base32,
    });

    const qrCodeDataUrl = await QRCode.toDataURL(secret.otpauth_url);

    return {
      secret: secret.base32,
      otpauthUri: secret.otpauth_url,
      qrCodeDataUrl,
      setupToken,
      message: 'Scan the QR code with your authenticator app, then enter the code to enable OTP.',
    };
  }

  /**
   * Confirm OTP setup after user verifies a code.
   *
   * @param {object} user
   * @param {{ otp_code: string, setupToken: string }} credentials
   */
  confirmOtpSetup(user, { otp_code, setupToken }) {
    if (user.otp_secret) throw new AuthError('OTP already enabled');

    const now = Math.floor(Date.now() / 1000);
    const temp = findTempToken(setupToken);

    if (
      !temp ||
      temp.expires_at < now ||
      temp.type !== 'otp_setup_pending' ||
      temp.user_id !== user.id
    ) {
      throw new TokenError('Setup token expired or invalid. Call /otp/setup again.');
    }

    const pendingSecret = temp.data;
    if (!pendingSecret) throw new TokenError('Setup token missing secret data');

    const speakeasy = require('speakeasy');
    const verified = speakeasy.totp.verify({
      secret: pendingSecret,
      encoding: 'base32',
      token: otp_code,
    });
    if (!verified) throw new TokenError('Invalid OTP code — setup not confirmed');

    updateUserOtp(user.id, pendingSecret);
    deleteTempToken(setupToken);
  }

  /**
   * Disable OTP for a user.
   *
   * @param {object} user
   * @param {{ otp_code: string }} credentials
   */
  disableOtp(user, { otp_code }) {
    if (!user.otp_secret) throw new AuthError('OTP not enabled');

    const otpAuth = this._authenticators.get('otp');
    const verified = otpAuth.verify({ username: user.username, otp_code }, this._authContext());
    if (!verified) throw new AuthError('Invalid OTP code');

    updateUserOtp(user.id, null);
  }

  // ─── Helpers ────────────────────────────────────────────────────────────────

  /**
   * Build the standard login response shape.
   *
   * @param {object} user
   * @param {object} session
   * @returns {{ success: true, token: string, user: object }}
   */
  _buildLoginResponse(user, session) {
    const subject = getSubjectById(user.subject_id);
    const policy = resolvePolicy(subject?.type);
    return {
      success: true,
      token: session.id,
      user: {
        id: user.id,
        username: user.username,
        subjectType: subject?.type,
        permissions: policy.getPermissions(),
      },
    };
  }

  /**
   * Build the /me response for an authenticated user.
   *
   * @param {object} user
   * @returns {object}
   */
  buildMeResponse(user) {
    const subject = getSubjectById(user.subject_id);
    const policy = resolvePolicy(subject?.type);
    return {
      id: user.id,
      username: user.username,
      subjectType: subject?.type,
      subjectLabel: policy.label,
      hasOtp: !!user.otp_secret,
      hasPasskey: !!user.passkey_credential_id,
      permissions: policy.getPermissions(),
      createdAt: user.created_at,
    };
  }
}

// ─── Singleton instance ────────────────────────────────────────────────────────
// Routes share one AuthService instance.
const authService = new AuthService();

module.exports = { AuthService, authService, TokenError, AuthError };
