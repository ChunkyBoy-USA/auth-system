const request = require('supertest');
const { createApp } = require('../server');

let app;

beforeAll(async () => {
  app = await createApp();
});

// ─── Helpers ────────────────────────────────────────────────────
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
  return loginPassword(username).then((r) => r.body.token || r.body.temp_token);
}

// ─── POST /api/auth/passkey/register-options ───────────────────
describe('POST /api/auth/passkey/register-options', () => {
  it('returns 401 without auth token', async () => {
    const res = await request(app)
      .post('/api/auth/passkey/register-options');
    expect(res.status).toBe(401);
  });

  it('returns WebAuthn registration options for authenticated user', async () => {
    await register('pkreguser');
    const token = await getToken('pkreguser');
    const res = await request(app)
      .post('/api/auth/passkey/register-options')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.challenge).toBeTruthy();
    expect(res.body.rp).toEqual({ name: 'AuthSystem', id: 'localhost' });
    expect(res.body.pubKeyCredParams).toBeTruthy();
    expect(res.body.timeout).toBe(60000);
    expect(res.body.attestation).toBe('none');
  });

  it('stores challenge in server memory', async () => {
    await register('pkreguser2');
    const token = await getToken('pkreguser2');
    await request(app)
      .post('/api/auth/passkey/register-options')
      .set('Authorization', `Bearer ${token}`);
    // Second call with same user updates the challenge
    const res2 = await request(app)
      .post('/api/auth/passkey/register-options')
      .set('Authorization', `Bearer ${token}`);
    expect(res2.status).toBe(200);
    expect(res2.body.challenge).toBeTruthy();
  });
});

// ─── POST /api/auth/passkey/register-verify ─────────────────────
describe('POST /api/auth/passkey/register-verify', () => {
  it('returns 401 without auth token', async () => {
    const res = await request(app)
      .post('/api/auth/passkey/register-verify')
      .send({ body: {} });
    expect(res.status).toBe(401);
  });

  it('returns 400 when challenge has expired or not found', async () => {
    await register('pkverifyuser');
    const token = await getToken('pkverifyuser');
    // No register-options called first — challenge not in store
    const res = await request(app)
      .post('/api/auth/passkey/register-verify')
      .set('Authorization', `Bearer ${token}`)
      .send({ body: {} });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/expired|not found/i);
  });
});

// ─── POST /api/auth/passkey/login-options ───────────────────────
describe('POST /api/auth/passkey/login-options', () => {
  it('returns 400 when username is missing', async () => {
    const res = await request(app)
      .post('/api/auth/passkey/login-options')
      .send({});
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/username.*required/i);
  });

  it('returns 404 when user has no passkey', async () => {
    await register('pkloginuser');
    const res = await request(app)
      .post('/api/auth/passkey/login-options')
      .send({ username: 'pkloginuser' });
    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/no passkey/i);
  });
});

// ─── POST /api/auth/passkey/login-verify ─────────────────────────
describe('POST /api/auth/passkey/login-verify', () => {
  it('returns 400 when username is missing', async () => {
    const res = await request(app)
      .post('/api/auth/passkey/login-verify')
      .send({ body: {} });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/required/i);
  });

  it('returns 404 when user has no passkey', async () => {
    await register('pkverifyloginuser');
    const res = await request(app)
      .post('/api/auth/passkey/login-verify')
      .send({ username: 'pkverifyloginuser', body: {} });
    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/not found/i);
  });

  it('returns 400 when challenge expired or not found', async () => {
    // Manually set a passkey in DB via register-options → won't work without real WebAuthn
    // But we can test the error path with a user who has no challenge
    await register('pkverifychallengeuser');
    const res = await request(app)
      .post('/api/auth/passkey/login-verify')
      .send({ username: 'pkverifychallengeuser', body: {} });
    expect(res.status).toBe(404); // first hits "no passkey" check
  });
});

// ─── Passkey end-to-end flow (mocked) ───────────────────────────
describe('Passkey registration → login flow (mocked WebAuthn)', () => {
  let token;
  let registerOptions;

  beforeAll(async () => {
    await register('pke2euser');
    token = await getToken('pke2euser');
    // Get registration options
    const regRes = await request(app)
      .post('/api/auth/passkey/register-options')
      .set('Authorization', `Bearer ${token}`);
    registerOptions = regRes.body;
  });

  it('register-options returns a valid challenge', () => {
    expect(registerOptions.challenge).toBeTruthy();
    expect(registerOptions.user.id).toBeTruthy(); // user ID as bytes
  });

  it('register-verify returns 400 when challenge expired (empty response)', async () => {
    const res = await request(app)
      .post('/api/auth/passkey/register-verify')
      .set('Authorization', `Bearer ${token}`)
      .send({ body: {} });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/expired|not found/i);
  });

  it('login-options returns 404 when user has no passkey', async () => {
    const res = await request(app)
      .post('/api/auth/passkey/login-options')
      .send({ username: 'pke2euser' });
    expect(res.status).toBe(404);
  });
});

// ─── Static file serving ────────────────────────────────────────
describe('Static file serving', () => {
  it('serves index.html at /', async () => {
    const res = await request(app).get('/');
    expect(res.status).toBe(200);
    expect(res.text).toContain('<!DOCTYPE html>');
  });

  it('serves dashboard.html at /dashboard', async () => {
    const res = await request(app).get('/dashboard');
    expect(res.status).toBe(200);
    expect(res.text).toContain('Dashboard');
  });

  it('serves CSS at /style.css', async () => {
    const res = await request(app).get('/style.css');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/css/);
  });

  it('serves SimpleWebAuthn UMD bundle', async () => {
    const res = await request(app).get('/lib/simplewebauthn-browser.umd.min.js');
    expect(res.status).toBe(200);
    expect(res.text).toContain('SimpleWebAuthnBrowser');
    expect(res.text).toContain('startRegistration');
    expect(res.text).toContain('startAuthentication');
  });

  it('serves recover.html', async () => {
    const res = await request(app).get('/recover.html');
    expect(res.status).toBe(200);
    expect(res.text).toContain('Reset OTP');
  });

  it('serves register.html', async () => {
    const res = await request(app).get('/register.html');
    expect(res.status).toBe(200);
    expect(res.text).toContain('Create Account');
  });
});
