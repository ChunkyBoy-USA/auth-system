const express = require('express');
const cors = require('cors');
const path = require('path');

const { initDb } = require('./src/db/database');
const { PasswordAuthenticator } = require('./src/auth/PasswordAuthenticator');
const { OtpAuthenticator } = require('./src/auth/OtpAuthenticator');
const { authService } = require('./src/auth/AuthService');
const { challengeStore } = require('./src/auth/ChallengeStore');

const authRouter = require('./src/routes/auth');
const passkeyRouter = require('./src/routes/passkey');

// Register all authenticators with the central AuthService.
// To add a new login method: create src/auth/<Method>Authenticator.js
// and register it here. No changes to routes or AuthService needed.
authService.register(new PasswordAuthenticator());
authService.register(new OtpAuthenticator());

// Builds and returns the Express app. Call `await createApp()` before using.
// Idempotent — initDb is safe to call multiple times.
async function createApp() {
  await initDb();

  const app = express();
  app.use(cors());
  app.use(express.json());
  app.use(express.static(path.join(__dirname, 'public')));

  app.use('/api/auth', authRouter);
  app.use('/api/auth/passkey', passkeyRouter);

  app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });
  app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
  });

  return app;
}

async function start() {
  const app = await createApp();
  const PORT = process.env.PORT || 3000;
  const HOST = process.env.HOST || '0.0.0.0';

  const server = app.listen(PORT, HOST, () => {
    console.log(`AuthSystem running at http://localhost:${PORT}`);
    console.log(`On your network try: http://<your-mac-ip>:${PORT}`);
  });

  // Clean up ChallengeStore background timer on shutdown so the process exits cleanly.
  server.on('close', () => {
    challengeStore.shutdown();
  });

  return app;
}

// Start server when run directly (not when imported as a module by tests)
if (require.main === module) {
  start().catch(console.error);
}

module.exports = { createApp, start };
