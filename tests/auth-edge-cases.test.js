/**
 * Tests for auth.js edge cases and error paths
 */

const request = require('supertest');
const { createApp } = require('../server');

describe('Auth edge cases and error handling', () => {
  let app;
  let counter = 0;
  const uid = () => `edgecase${Date.now()}-${++counter}`;

  beforeAll(async () => {
    app = await createApp();
  });

  async function register(username, password = 'pass123', subjectId = 1) {
    return request(app)
      .post('/api/auth/register')
      .send({ username, password, subjectId });
  }

  async function getToken(username, password = 'pass123') {
    const res = await request(app)
      .post('/api/auth/login/password')
      .send({ username, password });
    return res.body.token;
  }

  describe('POST /api/auth/login/password with OTP enabled', () => {
    it('returns mfa_pending when user has OTP enabled', async () => {
      const username = uid();
      await register(username);
      const token = await getToken(username);

      // Setup and enable OTP
      const setupRes = await request(app)
        .post('/api/auth/otp/setup')
        .set('Authorization', `Bearer ${token}`);

      const speakeasy = require('speakeasy');
      const validCode = speakeasy.totp({
        secret: setupRes.body.secret,
        encoding: 'base32'
      });

      await request(app)
        .post('/api/auth/otp/enable')
        .set('Authorization', `Bearer ${token}`)
        .send({ otp_code: validCode, setupToken: setupRes.body.setupToken });

      // Now login should return mfa_pending
      const loginRes = await request(app)
        .post('/api/auth/login/password')
        .send({ username, password: 'pass123' });

      expect(loginRes.status).toBe(200);
      expect(loginRes.body.mfa_pending).toBe(true);
      expect(loginRes.body.temp_token).toBeTruthy();
      expect(loginRes.body.message).toMatch(/OTP/i);
    });
  });

  describe('POST /api/auth/otp/disable edge cases', () => {
    it('returns 400 when OTP is not enabled', async () => {
      const username = uid();
      await register(username);
      const token = await getToken(username);

      const res = await request(app)
        .post('/api/auth/otp/disable')
        .set('Authorization', `Bearer ${token}`)
        .send({ otp_code: '123456' });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/not enabled/i);
    });

    it('returns 400 when otp_code is missing', async () => {
      const username = uid();
      await register(username);
      const token = await getToken(username);

      const res = await request(app)
        .post('/api/auth/otp/disable')
        .set('Authorization', `Bearer ${token}`)
        .send({});

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/required/i);
    });
  });

  describe('POST /api/auth/recover/reset-otp edge cases', () => {
    it('returns 400 when both username and password are missing', async () => {
      const res = await request(app)
        .post('/api/auth/recover/reset-otp')
        .send({});

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/required/i);
    });

    it('successfully resets OTP for user with OTP enabled', async () => {
      const username = uid();
      await register(username);
      const token = await getToken(username);

      // Setup and enable OTP
      const setupRes = await request(app)
        .post('/api/auth/otp/setup')
        .set('Authorization', `Bearer ${token}`);

      const speakeasy = require('speakeasy');
      const validCode = speakeasy.totp({
        secret: setupRes.body.secret,
        encoding: 'base32'
      });

      await request(app)
        .post('/api/auth/otp/enable')
        .set('Authorization', `Bearer ${token}`)
        .send({ otp_code: validCode, setupToken: setupRes.body.setupToken });

      // Reset OTP
      const resetRes = await request(app)
        .post('/api/auth/recover/reset-otp')
        .send({ username, password: 'pass123' });

      expect(resetRes.status).toBe(200);
      expect(resetRes.body.success).toBe(true);
      expect(resetRes.body.message).toMatch(/reset/i);
    });
  });

  describe('DELETE /api/auth/sessions/:id edge cases', () => {
    it('returns 404 when session does not exist', async () => {
      const username = uid();
      await register(username);
      const token = await getToken(username);

      const res = await request(app)
        .delete('/api/auth/sessions/non-existent-session-id')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(404);
      expect(res.body.error).toMatch(/not found/i);
    });

    it('returns 400 when trying to delete current session', async () => {
      const username = uid();
      await register(username);
      const token = await getToken(username);

      const res = await request(app)
        .delete(`/api/auth/sessions/${token}`)
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/current session/i);
    });
  });

  describe('POST /api/auth/mfa/verify edge cases', () => {
    it('returns 400 when temp_token is missing', async () => {
      const res = await request(app)
        .post('/api/auth/mfa/verify')
        .send({ otp_code: '123456' });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/required/i);
    });

    it('returns 400 when otp_code is missing', async () => {
      const res = await request(app)
        .post('/api/auth/mfa/verify')
        .send({ temp_token: 'some-token' });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/required/i);
    });

    it('returns 401 for invalid temp_token', async () => {
      const res = await request(app)
        .post('/api/auth/mfa/verify')
        .send({ temp_token: 'invalid-token', otp_code: '123456' });

      expect(res.status).toBe(401);
      expect(res.body.error).toMatch(/expired|invalid/i);
    });
  });

  describe('POST /api/auth/mfa/init edge cases', () => {
    it('returns 400 when username is missing', async () => {
      const res = await request(app)
        .post('/api/auth/mfa/init')
        .send({ password: 'pass123' });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/required/i);
    });

    it('returns 400 when password is missing', async () => {
      const res = await request(app)
        .post('/api/auth/mfa/init')
        .send({ username: 'someuser' });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/required/i);
    });

    it('returns 401 for non-existent user', async () => {
      const res = await request(app)
        .post('/api/auth/mfa/init')
        .send({ username: 'nonexistent', password: 'pass123' });

      expect(res.status).toBe(401);
      expect(res.body.error).toMatch(/invalid credentials/i);
    });

    it('returns 400 when user has not set up OTP', async () => {
      const username = uid();
      await register(username);

      const res = await request(app)
        .post('/api/auth/mfa/init')
        .send({ username, password: 'pass123' });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/not set up/i);
    });
  });
});
