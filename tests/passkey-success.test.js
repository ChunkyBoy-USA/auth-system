/**
 * Tests for passkey success paths.
 * These require mocking @simplewebauthn/server because real WebAuthn
 * verification needs credentials from a real browser.
 *
 * jest.mock is hoisted, so this runs before any require('server').
 */

// Mock @simplewebauthn/server — must be at top level (hoisted by Jest)
jest.mock('@simplewebauthn/server', () => {
  const actual = jest.requireActual('@simplewebauthn/server');
  return {
    ...actual,
    // Return thenables that resolve to valid mock options
    generateRegistrationOptions: jest.fn(() =>
      Promise.resolve({
        challenge: 'mock-register-challenge-12345',
        rp: { name: 'AuthSystem', id: 'localhost' },
        user: { id: 'mock-user-id', name: 'testuser', displayName: 'Test User' },
        pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
        timeout: 60000,
        attestation: 'none',
        excludeCredentials: [],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'preferred',
        },
      })
    ),
    generateAuthenticationOptions: jest.fn(() =>
      Promise.resolve({
        challenge: 'mock-auth-challenge-67890',
        rpId: 'localhost',
        timeout: 60000,
        userVerification: 'preferred',
        allowCredentials: [],
      })
    ),
    // Mock verification to return success with fake credential info
    verifyRegistrationResponse: jest.fn(() =>
      Promise.resolve({
        registrationInfo: {
          credentialID: Buffer.from('mock-credential-id-base64url=='),
          credentialPublicKey: Buffer.from('mock-public-key-base64url=='),
          counter: 0,
          credentialDeviceType: 'singleDevice',
          credentialBackedUp: false,
          credentialExcludedDevices: [],
        },
      })
    ),
    verifyAuthenticationResponse: jest.fn(() =>
      Promise.resolve({
        authenticationInfo: {
          newCounter: 1,
          authenticatorData: {
            counter: 1,
          },
        },
      })
    ),
  };
});

const request = require('supertest');
const { createApp } = require('../server');
const { isoBase64URL } = require('@simplewebauthn/server/helpers');

let app;

// Use a unique prefix per test to avoid DB collisions
let counter = 0;
function uniqueUser() {
  return `pksuccessuser${Date.now()}-${++counter}`;
}

beforeAll(async () => {
  app = await createApp();
});

// ─── Helpers ───────────────────────────────────────────────────
function register(username, subjectId = 1) {
  return request(app)
    .post('/api/auth/register')
    .send({ username, password: 'pass123', subjectId });
}

function loginPassword(username) {
  return request(app)
    .post('/api/auth/login/password')
    .send({ username, password: 'pass123' });
}

function getToken(username) {
  return loginPassword(username).then((r) => r.body.token);
}

// ─── POST /api/auth/passkey/register-verify — success ─────────
describe('POST /api/auth/passkey/register-verify (success)', () => {
  it('registers a passkey and updates user record', async () => {
    const username = uniqueUser();
    await register(username);
    const token = await getToken(username);

    // Step 1: Get registration options
    const optsRes = await request(app)
      .post('/api/auth/passkey/register-options')
      .set('Authorization', `Bearer ${token}`);
    expect(optsRes.status).toBe(200);
    expect(optsRes.body.challenge).toBeTruthy();

    // Step 2: Verify with mock credential (mocked @simplewebauthn/server)
    const mockCredId = Buffer.from('mock-cred-id').toString('base64url');
    const mockPubKey = Buffer.from('mock-pub-key').toString('base64url');

    // Override the mock to return the right credential ID
    const { verifyRegistrationResponse } = require('@simplewebauthn/server');
    verifyRegistrationResponse.mockResolvedValueOnce({
      registrationInfo: {
        credentialID: Buffer.from(mockCredId),
        credentialPublicKey: Buffer.from(mockPubKey),
        counter: 0,
        credentialDeviceType: 'singleDevice',
        credentialBackedUp: false,
        credentialExcludedDevices: [],
      },
    });

    const verifyRes = await request(app)
      .post('/api/auth/passkey/register-verify')
      .set('Authorization', `Bearer ${token}`)
      .send({ id: 'mock-credential-id', rawId: 'mock-credential-id', response: {} });
    expect(verifyRes.status).toBe(200);
    expect(verifyRes.body.success).toBe(true);

    // Step 3: Verify user now has a passkey
    const meRes = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${token}`);
    expect(meRes.body.hasPasskey).toBe(true);
  });

  it('returns 400 when verifyRegistrationResponse throws', async () => {
    const username = uniqueUser();
    await register(username);
    const token = await getToken(username);

    // Get options first
    await request(app)
      .post('/api/auth/passkey/register-options')
      .set('Authorization', `Bearer ${token}`);

    // Force the mock to throw
    const { verifyRegistrationResponse } = require('@simplewebauthn/server');
    verifyRegistrationResponse.mockRejectedValueOnce(new Error('Invalid attestation'));

    const res = await request(app)
      .post('/api/auth/passkey/register-verify')
      .set('Authorization', `Bearer ${token}`)
      .send({ id: 'bad-credential' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/registration failed/i);
  });
});

// ─── POST /api/auth/passkey/login-options — success ───────────
describe('POST /api/auth/passkey/login-options (success)', () => {
  it('returns assertion options for a user with a registered passkey', async () => {
    const username = uniqueUser();
    await register(username);
    const token = await getToken(username);

    // First register a passkey (mocked)
    const optsRes = await request(app)
      .post('/api/auth/passkey/register-options')
      .set('Authorization', `Bearer ${token}`);
    expect(optsRes.status).toBe(200);

    const mockCredId = Buffer.from('success-cred-id').toString('base64url');
    const mockPubKey = Buffer.from('success-pub-key').toString('base64url');
    const { verifyRegistrationResponse } = require('@simplewebauthn/server');
    verifyRegistrationResponse.mockResolvedValueOnce({
      registrationInfo: {
        credentialID: Buffer.from(mockCredId),
        credentialPublicKey: Buffer.from(mockPubKey),
        counter: 0,
        credentialDeviceType: 'singleDevice',
        credentialBackedUp: false,
        credentialExcludedDevices: [],
      },
    });

    await request(app)
      .post('/api/auth/passkey/register-verify')
      .set('Authorization', `Bearer ${token}`)
      .send({ id: 'success-cred-id' });

    // Now login-options should succeed
    const loginOptsRes = await request(app)
      .post('/api/auth/passkey/login-options')
      .send({ username });
    expect(loginOptsRes.status).toBe(200);
    expect(loginOptsRes.body.challenge).toBeTruthy();
    expect(loginOptsRes.body.rpId).toBe('localhost');
  });
});

// ─── POST /api/auth/passkey/login-verify — success ────────────
describe('POST /api/auth/passkey/login-verify (success)', () => {
  it('returns token after successful passkey verification', async () => {
    const username = uniqueUser();
    await register(username);
    const token = await getToken(username);

    // Register a passkey first
    const optsRes = await request(app)
      .post('/api/auth/passkey/register-options')
      .set('Authorization', `Bearer ${token}`);
    expect(optsRes.status).toBe(200);

    const mockCredId = Buffer.from('verify-cred-id').toString('base64url');
    const mockPubKey = Buffer.from('verify-pub-key').toString('base64url');
    const { verifyRegistrationResponse } = require('@simplewebauthn/server');
    verifyRegistrationResponse.mockResolvedValueOnce({
      registrationInfo: {
        credentialID: Buffer.from(mockCredId),
        credentialPublicKey: Buffer.from(mockPubKey),
        counter: 0,
        credentialDeviceType: 'singleDevice',
        credentialBackedUp: false,
        credentialExcludedDevices: [],
      },
    });

    await request(app)
      .post('/api/auth/passkey/register-verify')
      .set('Authorization', `Bearer ${token}`)
      .send({ id: 'verify-cred-id' });

    // Get login options
    const loginOptsRes = await request(app)
      .post('/api/auth/passkey/login-options')
      .send({ username });
    expect(loginOptsRes.status).toBe(200);
    const loginOpts = loginOptsRes.body;

    // Mock verifyAuthenticationResponse
    const { verifyAuthenticationResponse } = require('@simplewebauthn/server');
    verifyAuthenticationResponse.mockResolvedValueOnce({
      authenticationInfo: {
        newCounter: 5,
        authenticatorData: { counter: 5 },
      },
    });

    // Call login-verify with a mock assertion
    const verifyRes = await request(app)
      .post('/api/auth/passkey/login-verify')
      .send({ username, body: { id: mockCredId } });
    expect(verifyRes.status).toBe(200);
    expect(verifyRes.body.success).toBe(true);
    expect(verifyRes.body.token).toBeTruthy();
    expect(verifyRes.body.user.username).toBe(username);
  });

  it('returns 400 when verifyAuthenticationResponse throws', async () => {
    const username = uniqueUser();
    await register(username);
    const token = await getToken(username);

    // Register passkey
    await request(app)
      .post('/api/auth/passkey/register-options')
      .set('Authorization', `Bearer ${token}`);

    const mockCredId = Buffer.from('error-cred-id').toString('base64url');
    const mockPubKey = Buffer.from('error-pub-key').toString('base64url');
    const { verifyRegistrationResponse } = require('@simplewebauthn/server');
    verifyRegistrationResponse.mockResolvedValueOnce({
      registrationInfo: {
        credentialID: Buffer.from(mockCredId),
        credentialPublicKey: Buffer.from(mockPubKey),
        counter: 0,
        credentialDeviceType: 'singleDevice',
        credentialBackedUp: false,
        credentialExcludedDevices: [],
      },
    });

    await request(app)
      .post('/api/auth/passkey/register-verify')
      .set('Authorization', `Bearer ${token}`)
      .send({ id: 'error-cred-id' });

    // Set up login challenge
    await request(app)
      .post('/api/auth/passkey/login-options')
      .send({ username });

    // Force auth verify to throw
    const { verifyAuthenticationResponse } = require('@simplewebauthn/server');
    verifyAuthenticationResponse.mockRejectedValueOnce(new Error('Signature verification failed'));

    const res = await request(app)
      .post('/api/auth/passkey/login-verify')
      .send({ username, body: { id: mockCredId } });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/verification failed/i);
  });
});
