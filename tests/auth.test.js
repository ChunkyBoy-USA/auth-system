const request = require('supertest');
const { createApp } = require('../server');

// Reuse a single app instance across all tests for speed.
// Each test uses unique usernames to avoid collisions.
describe('POST /api/auth/login/otp — OTP not set up', () => {
  let app;

  beforeAll(async () => {
    app = await createApp();
  });

  it('returns 400 with recovery_url when OTP is not set up', async () => {
    // Register a fresh user (no OTP)
    await request(app)
      .post('/api/auth/register')
      .send({ username: 'nootpuser', password: 'pass123', subjectId: 1 });

    const res = await request(app)
      .post('/api/auth/login/otp')
      .send({ username: 'nootpuser', otp_code: '123456' });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/OTP not set up/i);
    expect(res.body.recovery_url).toBe('/recover.html');
  });

  it('returns 400 when username is missing', async () => {
    const res = await request(app)
      .post('/api/auth/login/otp')
      .send({ otp_code: '123456' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/required/i);
  });

  it('returns 400 when otp_code is missing', async () => {
    const res = await request(app)
      .post('/api/auth/login/otp')
      .send({ username: 'someuser' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/required/i);
  });

  it('returns 401 for non-existent user', async () => {
    const res = await request(app)
      .post('/api/auth/login/otp')
      .send({ username: 'ghostuser999', otp_code: '123456' });
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/Invalid credentials/i);
  });

  it('returns 401 for wrong OTP code when OTP is set', async () => {
    // Register + enable OTP for this user
    await request(app)
      .post('/api/auth/register')
      .send({ username: 'wrongcodeuser', password: 'pass123', subjectId: 1 });

    const loginRes = await request(app)
      .post('/api/auth/login/password')
      .send({ username: 'wrongcodeuser', password: 'pass123' });
    const token = loginRes.body.token;

    await request(app)
      .post('/api/auth/otp/setup')
      .set('Authorization', `Bearer ${token}`);

    const res = await request(app)
      .post('/api/auth/login/otp')
      .send({ username: 'wrongcodeuser', otp_code: '000000' });
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/Invalid OTP/i);
  });
});

describe('POST /api/auth/recover/reset-otp', () => {
  let app;

  beforeAll(async () => {
    app = await createApp();
  });

  it('resets OTP and allows subsequent password-only login', async () => {
    // Register + enable OTP
    await request(app)
      .post('/api/auth/register')
      .send({ username: 'recoveruser', password: 'pass123', subjectId: 1 });

    const loginRes = await request(app)
      .post('/api/auth/login/password')
      .send({ username: 'recoveruser', password: 'pass123' });
    const token = loginRes.body.token;

    await request(app)
      .post('/api/auth/otp/setup')
      .set('Authorization', `Bearer ${token}`);

    // Verify MFA is required after enabling OTP
    const beforeRes = await request(app)
      .post('/api/auth/login/password')
      .send({ username: 'recoveruser', password: 'pass123' });
    expect(beforeRes.body.mfa_pending).toBe(true);

    // Reset OTP via recovery endpoint
    const recoverRes = await request(app)
      .post('/api/auth/recover/reset-otp')
      .send({ username: 'recoveruser', password: 'pass123' });
    expect(recoverRes.status).toBe(200);
    expect(recoverRes.body.success).toBe(true);
    expect(recoverRes.body.message).toMatch(/reset/i);

    // Login now succeeds without MFA
    const afterRes = await request(app)
      .post('/api/auth/login/password')
      .send({ username: 'recoveruser', password: 'pass123' });
    expect(afterRes.status).toBe(200);
    expect(afterRes.body.success).toBe(true);
    expect(afterRes.body.token).toBeTruthy();
  });

  it('returns 401 for wrong password', async () => {
    const res = await request(app)
      .post('/api/auth/recover/reset-otp')
      .send({ username: 'recoveruser', password: 'wrongpassword' });
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/Invalid credentials/i);
  });

  it('returns 401 for non-existent user', async () => {
    const res = await request(app)
      .post('/api/auth/recover/reset-otp')
      .send({ username: 'ghostuser', password: 'pass123' });
    expect(res.status).toBe(401);
  });

  it('returns 400 when username is missing', async () => {
    const res = await request(app)
      .post('/api/auth/recover/reset-otp')
      .send({ password: 'pass123' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/required/i);
  });

  it('returns 400 when password is missing', async () => {
    const res = await request(app)
      .post('/api/auth/recover/reset-otp')
      .send({ username: 'recoveruser' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/required/i);
  });

  it('returns 400 when both fields are missing', async () => {
    const res = await request(app)
      .post('/api/auth/recover/reset-otp')
      .send({});
    expect(res.status).toBe(400);
  });
});

describe('POST /api/auth/mfa/init and /mfa/verify', () => {
  let app;

  beforeAll(async () => {
    app = await createApp();
  });

  it('mfa/init returns mfa_pending + temp_token when credentials are valid and OTP is set', async () => {
    // Register + enable OTP
    await request(app)
      .post('/api/auth/register')
      .send({ username: 'mfauser', password: 'pass123', subjectId: 2 });

    const loginRes = await request(app)
      .post('/api/auth/login/password')
      .send({ username: 'mfauser', password: 'pass123' });
    const token = loginRes.body.token;

    await request(app)
      .post('/api/auth/otp/setup')
      .set('Authorization', `Bearer ${token}`);

    // mfa/init should succeed
    const mfaRes = await request(app)
      .post('/api/auth/mfa/init')
      .send({ username: 'mfauser', password: 'pass123' });
    expect(mfaRes.status).toBe(200);
    expect(mfaRes.body.mfa_pending).toBe(true);
    expect(mfaRes.body.temp_token).toBeTruthy();
  });

  it('mfa/init returns 401 when password is wrong', async () => {
    const res = await request(app)
      .post('/api/auth/mfa/init')
      .send({ username: 'mfauser', password: 'wrongpassword' });
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/Invalid credentials/i);
  });

  it('mfa/init returns 400 when OTP not set up', async () => {
    await request(app)
      .post('/api/auth/register')
      .send({ username: 'mfanootpuser', password: 'pass123', subjectId: 2 });

    const res = await request(app)
      .post('/api/auth/mfa/init')
      .send({ username: 'mfanootpuser', password: 'pass123' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/not set up/i);
  });

  it('mfa/verify returns 401 for invalid temp_token', async () => {
    const res = await request(app)
      .post('/api/auth/mfa/verify')
      .send({ temp_token: 'not-a-real-token', otp_code: '000000' });
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/expired|invalid/i);
  });

  it('mfa/verify returns 400 when temp_token is missing', async () => {
    const res = await request(app)
      .post('/api/auth/mfa/verify')
      .send({ otp_code: '123456' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/required/i);
  });

  it('mfa/verify returns 400 when otp_code is missing', async () => {
    const res = await request(app)
      .post('/api/auth/mfa/verify')
      .send({ temp_token: 'sometoken' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/required/i);
  });
});
