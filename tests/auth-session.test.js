const request = require('supertest');
const { createApp } = require('../server');

let app;
let counter = 0;
function uid(prefix = 'as') {
  return `${prefix}${Date.now()}-${++counter}`;
}

beforeAll(async () => {
  app = await createApp();
});

// ─── Helpers ────────────────────────────────────────────────────
function register(username, subjectId = 1) {
  return request(app)
    .post('/api/auth/register')
    .send({ username, password: 'pass123', subjectId });
}

function loginPassword(username, password = 'pass123') {
  return request(app)
    .post('/api/auth/login/password')
    .send({ username, password });
}

function getToken(username) {
  return loginPassword(username).then((r) => r.body.token);
}

// ─── POST /api/auth/register ───────────────────────────────────
describe('POST /api/auth/register', () => {
  it('returns 400 when username is missing', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ password: 'pass123', subjectId: 1 });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/required/i);
  });

  it('returns 400 when password is missing', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ username: uid('un'), subjectId: 1 });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/required/i);
  });

  it('returns 400 when subjectId is missing', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ username: uid('un2'), password: 'pass123' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/required/i);
  });

  it('returns 400 for invalid subjectId', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ username: uid('bsbj'), password: 'pass123', subjectId: 99 });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid subjectId/i);
  });

  it('returns 409 for duplicate username', async () => {
    const name = uid('dup');
    await register(name);
    const res = await register(name);
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/already taken/i);
  });

  it('returns user object on success', async () => {
    const name = uid('new');
    const res = await register(name);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.user.id).toBeTruthy();
    expect(res.body.user.username).toBe(name);
    expect(res.body.user.subjectType).toBe('member');
  });

  it('registers community_staff subject correctly', async () => {
    const res = await register(uid('comm'), 2);
    expect(res.body.user.subjectType).toBe('community_staff');
  });

  it('registers platform_staff subject correctly', async () => {
    const res = await register(uid('plat'), 3);
    expect(res.body.user.subjectType).toBe('platform_staff');
  });
});

// ─── POST /api/auth/login/password ──────────────────────────────
describe('POST /api/auth/login/password', () => {
  it('returns 400 when username is missing', async () => {
    const res = await request(app)
      .post('/api/auth/login/password')
      .send({ password: 'pass123' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/required/i);
  });

  it('returns 400 when password is missing', async () => {
    const res = await request(app)
      .post('/api/auth/login/password')
      .send({ username: uid('pwdmiss') });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/required/i);
  });

  it('returns 401 for non-existent user', async () => {
    const res = await request(app)
      .post('/api/auth/login/password')
      .send({ username: uid('ghost'), password: 'pass123' });
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/invalid credentials/i);
  });

  it('returns 401 for wrong password', async () => {
    const name = uid('pwdwrong');
    await register(name);
    const res = await request(app)
      .post('/api/auth/login/password')
      .send({ username: name, password: 'wrongpassword' });
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/invalid credentials/i);
  });

  it('returns token on success', async () => {
    const name = uid('pwdok');
    await register(name);
    const res = await request(app)
      .post('/api/auth/login/password')
      .send({ username: name, password: 'pass123' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.token).toBeTruthy();
    expect(res.body.user.username).toBe(name);
  });
});

// ─── POST /api/auth/logout ─────────────────────────────────────
describe('POST /api/auth/logout', () => {
  it('returns 401 without auth token', async () => {
    const res = await request(app).post('/api/auth/logout');
    expect(res.status).toBe(401);
  });

  it('returns success on valid logout', async () => {
    const name = uid('logout');
    await register(name);
    const token = await getToken(name);
    const res = await request(app)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  it('token is invalidated after logout', async () => {
    const name = uid('logout2');
    await register(name);
    const token = await getToken(name);
    await request(app)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${token}`);
    const meRes = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${token}`);
    expect(meRes.status).toBe(401);
  });
});

// ─── POST /api/auth/logout-all ─────────────────────────────────
describe('POST /api/auth/logout-all', () => {
  it('returns 401 without auth token', async () => {
    const res = await request(app).post('/api/auth/logout-all');
    expect(res.status).toBe(401);
  });

  it('returns success on logout-all', async () => {
    const name = uid('logoutall');
    await register(name);
    const token = await getToken(name);
    const res = await request(app)
      .post('/api/auth/logout-all')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });
});

// ─── GET /api/auth/me ──────────────────────────────────────────
describe('GET /api/auth/me', () => {
  it('returns 401 without auth token', async () => {
    const res = await request(app).get('/api/auth/me');
    expect(res.status).toBe(401);
  });

  it('returns user info with hasOtp and hasPasskey fields', async () => {
    const name = uid('me');
    await register(name);
    const token = await getToken(name);
    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.id).toBeTruthy();
    expect(res.body.username).toBe(name);
    expect(res.body.subjectType).toBe('member');
    expect(res.body.hasOtp).toBe(false);
    expect(res.body.hasPasskey).toBe(false);
    expect(res.body.createdAt).toBeTruthy();
  });
});

// ─── GET /api/auth/sessions ───────────────────────────────────
describe('GET /api/auth/sessions', () => {
  it('returns 401 without auth token', async () => {
    const res = await request(app).get('/api/auth/sessions');
    expect(res.status).toBe(401);
  });

  it('returns session list for authenticated user', async () => {
    const name = uid('sess');
    await register(name);
    const token = await getToken(name);
    const res = await request(app)
      .get('/api/auth/sessions')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBeGreaterThan(0);
    expect(res.body[0].id).toBeTruthy();
    expect(res.body[0].deviceName).toBeTruthy();
    expect(res.body[0].ipAddress).toBeTruthy();
    expect(res.body[0].isCurrent).toBe(true);
  });
});

// ─── DELETE /api/auth/sessions/:id ────────────────────────────
describe('DELETE /api/auth/sessions/:id', () => {
  it('returns 401 without auth token', async () => {
    const res = await request(app).delete('/api/auth/sessions/fake-session-id');
    expect(res.status).toBe(401);
  });

  it('returns 404 for non-existent session', async () => {
    const name = uid('revoke1');
    await register(name);
    const token = await getToken(name);
    const res = await request(app)
      .delete('/api/auth/sessions/fake-session-id')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/not found/i);
  });

  it('returns 400 when trying to revoke current session', async () => {
    const name = uid('revoke2');
    await register(name);
    const token = await getToken(name);
    const sessRes = await request(app)
      .get('/api/auth/sessions')
      .set('Authorization', `Bearer ${token}`);
    const currentSessionId = sessRes.body.find((s) => s.isCurrent).id;
    const res = await request(app)
      .delete(`/api/auth/sessions/${currentSessionId}`)
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/current session/i);
  });
});

// ─── POST /api/auth/otp/setup ─────────────────────────────────
describe('POST /api/auth/otp/setup', () => {
  it('returns 401 without auth token', async () => {
    const res = await request(app).post('/api/auth/otp/setup');
    expect(res.status).toBe(401);
  });

  it('returns 400 if OTP already set up', async () => {
    const name = uid('otpalready');
    await register(name);
    const token = await getToken(name);
    // Set up OTP once
    await request(app)
      .post('/api/auth/otp/setup')
      .set('Authorization', `Bearer ${token}`);
    // Try again — should fail
    const res = await request(app)
      .post('/api/auth/otp/setup')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/already/i);
  });

  it('returns secret and QR code on success', async () => {
    const name = uid('otpsetup');
    await register(name);
    const token = await getToken(name);
    const res = await request(app)
      .post('/api/auth/otp/setup')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.secret).toBeTruthy();
    expect(res.body.otpauthUri).toMatch(/otpauth:\/\/totp\//);
    expect(res.body.qrCodeDataUrl).toMatch(/^data:image\/png;base64,/);
  });
});

// ─── POST /api/auth/otp/enable ────────────────────────────────
describe('POST /api/auth/otp/enable', () => {
  it('returns 401 without auth token', async () => {
    const res = await request(app)
      .post('/api/auth/otp/enable')
      .send({ otp_code: '000000' });
    expect(res.status).toBe(401);
  });

  it('returns 400 when otp_code is missing', async () => {
    const name = uid('ennootp');
    await register(name);
    const token = await getToken(name);
    const res = await request(app)
      .post('/api/auth/otp/enable')
      .set('Authorization', `Bearer ${token}`)
      .send({});
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/required/i);
  });

  it('returns 400 when OTP not set up first', async () => {
    const name = uid('ennotsetup');
    await register(name);
    const token = await getToken(name);
    const res = await request(app)
      .post('/api/auth/otp/enable')
      .set('Authorization', `Bearer ${token}`)
      .send({ otp_code: '000000' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/setup/i);
  });

  it('returns 401 for wrong OTP code', async () => {
    const name = uid('enwrong');
    await register(name);
    const token = await getToken(name);
    // Set up OTP
    await request(app)
      .post('/api/auth/otp/setup')
      .set('Authorization', `Bearer ${token}`);
    // Try to enable with wrong code
    const res = await request(app)
      .post('/api/auth/otp/enable')
      .set('Authorization', `Bearer ${token}`)
      .send({ otp_code: '000000' });
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/invalid/i);
  });
});

// ─── POST /api/auth/otp/disable ───────────────────────────────
describe('POST /api/auth/otp/disable', () => {
  it('returns 401 without auth token', async () => {
    const res = await request(app)
      .post('/api/auth/otp/disable')
      .send({ otp_code: '000000' });
    expect(res.status).toBe(401);
  });

  it('returns 400 when otp_code is missing', async () => {
    const name = uid('disnootp');
    await register(name);
    const token = await getToken(name);
    const res = await request(app)
      .post('/api/auth/otp/disable')
      .set('Authorization', `Bearer ${token}`)
      .send({});
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/required/i);
  });

  it('returns 400 when OTP is not enabled', async () => {
    const name = uid('disnotenabled');
    await register(name);
    const token = await getToken(name);
    const res = await request(app)
      .post('/api/auth/otp/disable')
      .set('Authorization', `Bearer ${token}`)
      .send({ otp_code: '000000' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/not enabled/i);
  });

  it('returns 401 for wrong OTP code when disabling', async () => {
    const name = uid('diswrong');
    await register(name);
    const token = await getToken(name);
    // Set up OTP first
    await request(app)
      .post('/api/auth/otp/setup')
      .set('Authorization', `Bearer ${token}`);
    // Try to disable with wrong code
    const res = await request(app)
      .post('/api/auth/otp/disable')
      .set('Authorization', `Bearer ${token}`)
      .send({ otp_code: '000000' });
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/invalid/i);
  });

  it('successfully disables OTP with correct code', async () => {
    const name = uid('dissuccess');
    await register(name);
    const token = await getToken(name);
    // Set up OTP
    const setupRes = await request(app)
      .post('/api/auth/otp/setup')
      .set('Authorization', `Bearer ${token}`);
    const secret = setupRes.body.secret;
    // Enable OTP with a valid code
    const speakeasy = require('speakeasy');
    const validCode = speakeasy.totp({ secret, encoding: 'base32' });
    await request(app)
      .post('/api/auth/otp/enable')
      .set('Authorization', `Bearer ${token}`)
      .send({ otp_code: validCode });
    // Disable with correct code
    const disableRes = await request(app)
      .post('/api/auth/otp/disable')
      .set('Authorization', `Bearer ${token}`)
      .send({ otp_code: validCode });
    expect(disableRes.status).toBe(200);
    expect(disableRes.body.success).toBe(true);
    expect(disableRes.body.message).toMatch(/disabled/i);
  });
});
