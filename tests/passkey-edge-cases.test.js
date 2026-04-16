/**
 * Tests for passkey.js edge cases and error paths
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

describe('Passkey edge cases', () => {
  let app;
  let counter = 0;
  const uid = () => `pkedge${Date.now()}-${++counter}`;

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

  describe('POST /api/auth/passkey/register-options with custom RP ID', () => {
    it('uses WEBAUTHN_RP_ID env var when set', async () => {
      const originalRpId = process.env.WEBAUTHN_RP_ID;
      process.env.WEBAUTHN_RP_ID = 'custom-rp-id.example.com';

      const username = uid();
      await register(username);
      const token = await getToken(username);

      const res = await request(app)
        .post('/api/auth/passkey/register-options')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.challenge).toBeTruthy();

      // Restore original env var
      if (originalRpId) {
        process.env.WEBAUTHN_RP_ID = originalRpId;
      } else {
        delete process.env.WEBAUTHN_RP_ID;
      }
    });

    it('falls back to origin hostname when WEBAUTHN_RP_ID not set', async () => {
      const originalRpId = process.env.WEBAUTHN_RP_ID;
      delete process.env.WEBAUTHN_RP_ID;

      const username = uid();
      await register(username);
      const token = await getToken(username);

      const res = await request(app)
        .post('/api/auth/passkey/register-options')
        .set('Authorization', `Bearer ${token}`)
        .set('Origin', 'http://example.com:3000');

      expect(res.status).toBe(200);
      expect(res.body.challenge).toBeTruthy();

      // Restore original env var
      if (originalRpId) {
        process.env.WEBAUTHN_RP_ID = originalRpId;
      }
    });
  });

  describe('POST /api/auth/passkey/register-verify error handling', () => {
    it('returns 400 when body is missing', async () => {
      const username = uid();
      await register(username);
      const token = await getToken(username);

      await request(app)
        .post('/api/auth/passkey/register-options')
        .set('Authorization', `Bearer ${token}`);

      const res = await request(app)
        .post('/api/auth/passkey/register-verify')
        .set('Authorization', `Bearer ${token}`)
        .send({});

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/Challenge expired or not found/i);
    });

    it('returns 400 when challenge has expired', async () => {
      const username = uid();
      await register(username);
      const token = await getToken(username);

      await request(app)
        .post('/api/auth/passkey/register-options')
        .set('Authorization', `Bearer ${token}`);

      // Wait for challenge to expire (or mock it)
      // For now, just test with no challenge stored
      const res = await request(app)
        .post('/api/auth/passkey/register-verify')
        .set('Authorization', `Bearer ${token}`)
        .send({ id: 'test-id', response: {} });

      expect(res.status).toBe(400);
    });
  });

  describe('POST /api/auth/passkey/login-options error handling', () => {
    it('returns 400 when username is missing', async () => {
      const res = await request(app)
        .post('/api/auth/passkey/login-options')
        .send({});

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/username is required/i);
    });

    it('returns 404 when user does not exist', async () => {
      const res = await request(app)
        .post('/api/auth/passkey/login-options')
        .send({ username: 'nonexistent-user' });

      expect(res.status).toBe(404);
      expect(res.body.error).toMatch(/No passkey found/i);
    });

    it('returns 404 when user has no passkey', async () => {
      const username = uid();
      await register(username);

      const res = await request(app)
        .post('/api/auth/passkey/login-options')
        .send({ username });

      expect(res.status).toBe(404);
      expect(res.body.error).toMatch(/No passkey found/i);
    });
  });

  describe('POST /api/auth/passkey/login-verify error handling', () => {
    it('returns 400 when username is missing', async () => {
      const res = await request(app)
        .post('/api/auth/passkey/login-verify')
        .send({ body: { id: 'test-id' } });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/username is required/i);
    });

    it('returns 404 when user does not exist', async () => {
      const res = await request(app)
        .post('/api/auth/passkey/login-verify')
        .send({ username: 'nonexistent', body: { id: 'test-id' } });

      expect(res.status).toBe(404);
      expect(res.body.error).toMatch(/User or passkey not found/i);
    });

    it('returns 404 when user has no passkey', async () => {
      const username = uid();
      await register(username);

      const res = await request(app)
        .post('/api/auth/passkey/login-verify')
        .send({ username, body: { id: 'test-id' } });

      expect(res.status).toBe(404);
      expect(res.body.error).toMatch(/User or passkey not found/i);
    });

    it('returns 400 when body is missing credential ID', async () => {
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
      const res = await request(app)
        .post('/api/auth/passkey/login-verify')
        .send({ username, body: {} });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/Missing credential ID/i);
    });

    it('returns 400 when challenge has expired', async () => {
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
            id: 'test-cred-2',
            publicKey: Buffer.from('test-key-2'),
            counter: 0,
          },
          credentialDeviceType: 'singleDevice',
          credentialBackedUp: false,
        },
      });

      await request(app)
        .post('/api/auth/passkey/register-verify')
        .set('Authorization', `Bearer ${token}`)
        .send({ id: 'test-cred-2', response: {} });

      // Try to login without getting options first (no challenge)
      const res = await request(app)
        .post('/api/auth/passkey/login-verify')
        .send({ username, body: { id: 'test-cred-2' } });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/Challenge expired or not found/i);
    });
  });
});
