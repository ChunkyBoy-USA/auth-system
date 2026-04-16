/**
 * Tests for passkey credential structure handling.
 * Covers both old and new @simplewebauthn/server response formats.
 */

const request = require('supertest');
const { createApp } = require('../server');

// Mock @simplewebauthn/server
jest.mock('@simplewebauthn/server', () => {
  const actual = jest.requireActual('@simplewebauthn/server');
  return {
    ...actual,
    generateRegistrationOptions: jest.fn(() =>
      Promise.resolve({
        challenge: 'test-challenge',
        rp: { name: 'AuthSystem', id: 'localhost' },
        user: { id: 'user-id', name: 'testuser', displayName: 'Test User' },
        pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
        timeout: 60000,
      })
    ),
    generateAuthenticationOptions: jest.fn(() =>
      Promise.resolve({
        challenge: 'auth-challenge',
        rpId: 'localhost',
        timeout: 60000,
        allowCredentials: [],
      })
    ),
    verifyRegistrationResponse: jest.fn(),
    verifyAuthenticationResponse: jest.fn(),
  };
});

describe('Passkey credential structure handling', () => {
  let app;
  let counter = 0;
  const uid = () => `credtest${Date.now()}-${++counter}`;

  beforeAll(async () => {
    app = await createApp();
  });

  async function register(username) {
    return request(app)
      .post('/api/auth/register')
      .send({ username, password: 'pass123', subjectId: 1 });
  }

  async function getToken(username) {
    const res = await request(app)
      .post('/api/auth/login/password')
      .send({ username, password: 'pass123' });
    return res.body.token;
  }

  describe('Registration with v9+ credential structure', () => {
    it('handles credential.id and credential.publicKey format', async () => {
      const username = uid();
      await register(username);
      const token = await getToken(username);

      // Get registration options
      await request(app)
        .post('/api/auth/passkey/register-options')
        .set('Authorization', `Bearer ${token}`);

      // Mock v9+ format with credential object
      const { verifyRegistrationResponse } = require('@simplewebauthn/server');
      verifyRegistrationResponse.mockResolvedValueOnce({
        registrationInfo: {
          credential: {
            id: 'test-cred-id-v9',
            publicKey: Buffer.from('test-pub-key-v9'),
            counter: 0,
          },
          credentialDeviceType: 'singleDevice',
          credentialBackedUp: false,
        },
      });

      const res = await request(app)
        .post('/api/auth/passkey/register-verify')
        .set('Authorization', `Bearer ${token}`)
        .send({ id: 'test-cred-id', response: {} });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      // Verify passkey was saved
      const meRes = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${token}`);
      expect(meRes.body.hasPasskey).toBe(true);
    });

    it('handles legacy credentialID and credentialPublicKey format', async () => {
      const username = uid();
      await register(username);
      const token = await getToken(username);

      await request(app)
        .post('/api/auth/passkey/register-options')
        .set('Authorization', `Bearer ${token}`);

      // Mock older v9 format with credentialID
      const { verifyRegistrationResponse } = require('@simplewebauthn/server');
      verifyRegistrationResponse.mockResolvedValueOnce({
        registrationInfo: {
          credentialID: Buffer.from('test-cred-id-legacy'),
          credentialPublicKey: Buffer.from('test-pub-key-legacy'),
          counter: 0,
          credentialDeviceType: 'singleDevice',
          credentialBackedUp: false,
        },
      });

      const res = await request(app)
        .post('/api/auth/passkey/register-verify')
        .set('Authorization', `Bearer ${token}`)
        .send({ id: 'test-cred-id', response: {} });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('returns error for unexpected credential format', async () => {
      const username = uid();
      await register(username);
      const token = await getToken(username);

      await request(app)
        .post('/api/auth/passkey/register-options')
        .set('Authorization', `Bearer ${token}`);

      // Mock with neither format
      const { verifyRegistrationResponse } = require('@simplewebauthn/server');
      verifyRegistrationResponse.mockResolvedValueOnce({
        registrationInfo: {
          // Missing both credential and credentialID
          counter: 0,
        },
      });

      const res = await request(app)
        .post('/api/auth/passkey/register-verify')
        .set('Authorization', `Bearer ${token}`)
        .send({ id: 'test-cred-id', response: {} });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/Unexpected credential format/i);
    });
  });

  describe('Login-verify with username and body parameters', () => {
    it('correctly extracts username and body from request', async () => {
      const username = uid();
      await register(username);
      const token = await getToken(username);

      // Register a passkey first
      await request(app)
        .post('/api/auth/passkey/register-options')
        .set('Authorization', `Bearer ${token}`);

      const { verifyRegistrationResponse } = require('@simplewebauthn/server');
      verifyRegistrationResponse.mockResolvedValueOnce({
        registrationInfo: {
          credential: {
            id: 'login-test-cred',
            publicKey: Buffer.from('login-test-key'),
            counter: 0,
          },
          credentialDeviceType: 'singleDevice',
          credentialBackedUp: false,
        },
      });

      await request(app)
        .post('/api/auth/passkey/register-verify')
        .set('Authorization', `Bearer ${token}`)
        .send({ id: 'login-test-cred', response: {} });

      // Get login options
      await request(app)
        .post('/api/auth/passkey/login-options')
        .send({ username });

      // Mock authentication verification
      const { verifyAuthenticationResponse } = require('@simplewebauthn/server');
      verifyAuthenticationResponse.mockResolvedValueOnce({
        authenticationInfo: {
          newCounter: 1,
        },
      });

      // Test login with username and body structure
      const loginRes = await request(app)
        .post('/api/auth/passkey/login-verify')
        .send({
          username,
          body: {
            id: 'login-test-cred',
            rawId: 'login-test-cred',
            response: {
              authenticatorData: 'mock-data',
              clientDataJSON: 'mock-client-data',
              signature: 'mock-signature',
            },
            type: 'public-key',
          },
        });

      expect(loginRes.status).toBe(200);
      expect(loginRes.body.success).toBe(true);
      expect(loginRes.body.token).toBeTruthy();
      expect(loginRes.body.user.username).toBe(username);
    });

    it('returns 400 when body is missing credential ID', async () => {
      const username = uid();
      await register(username);
      const token = await getToken(username);

      // Register a passkey
      await request(app)
        .post('/api/auth/passkey/register-options')
        .set('Authorization', `Bearer ${token}`);

      const { verifyRegistrationResponse } = require('@simplewebauthn/server');
      verifyRegistrationResponse.mockResolvedValueOnce({
        registrationInfo: {
          credential: {
            id: 'test-cred',
            publicKey: Buffer.from('test-key'),
            counter: 0,
          },
          credentialDeviceType: 'singleDevice',
          credentialBackedUp: false,
        },
      });

      await request(app)
        .post('/api/auth/passkey/register-verify')
        .set('Authorization', `Bearer ${token}`)
        .send({ id: 'test-cred', response: {} });

      // Get login options
      await request(app)
        .post('/api/auth/passkey/login-options')
        .send({ username });

      // Try to login without body.id
      const loginRes = await request(app)
        .post('/api/auth/passkey/login-verify')
        .send({
          username,
          body: {
            // Missing id field
            response: {},
          },
        });

      expect(loginRes.status).toBe(400);
      expect(loginRes.body.error).toMatch(/Missing credential ID/i);
    });

    it('returns 400 when username is missing', async () => {
      const res = await request(app)
        .post('/api/auth/passkey/login-verify')
        .send({
          body: { id: 'some-id', response: {} },
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/username is required/i);
    });
  });
});
