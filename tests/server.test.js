/**
 * Tests for server.js entry point and static file serving
 */

const request = require('supertest');
const { createApp } = require('../server');

describe('Server static file serving', () => {
  let app;

  beforeAll(async () => {
    app = await createApp();
  });

  it('serves index.html at /', async () => {
    const res = await request(app).get('/');
    expect(res.status).toBe(200);
    expect(res.text).toContain('AuthSystem');
  });

  it('serves dashboard.html at /dashboard', async () => {
    const res = await request(app).get('/dashboard');
    expect(res.status).toBe(200);
    expect(res.text).toContain('Dashboard');
  });

  it('serves static CSS files', async () => {
    const res = await request(app).get('/style.css');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/css/);
  });

  it('serves SimpleWebAuthn browser library', async () => {
    const res = await request(app).get('/lib/simplewebauthn-browser.umd.min.js');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/javascript/);
  });

  it('serves recover.html', async () => {
    const res = await request(app).get('/recover.html');
    expect(res.status).toBe(200);
    expect(res.text).toContain('Reset OTP');
  });

  it('serves register.html', async () => {
    const res = await request(app).get('/register.html');
    expect(res.status).toBe(200);
    expect(res.text).toContain('Register');
  });

  it('returns 404 for non-existent routes', async () => {
    const res = await request(app).get('/non-existent-route');
    expect(res.status).toBe(404);
  });
});

describe('Server initialization', () => {
  it('createApp returns an Express app', async () => {
    const app = await createApp();
    expect(app).toBeDefined();
    expect(typeof app.listen).toBe('function');
  });

  it('createApp is idempotent (can be called multiple times)', async () => {
    const app1 = await createApp();
    const app2 = await createApp();
    expect(app1).toBeDefined();
    expect(app2).toBeDefined();
  });
});

