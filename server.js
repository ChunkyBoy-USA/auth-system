const express = require('express');
const cors = require('cors');
const path = require('path');

const { initDb } = require('./src/db/database');

const authRouter = require('./src/routes/auth');
const passkeyRouter = require('./src/routes/passkey');

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
  app.listen(PORT, () => {
    console.log(`AuthSystem running at http://localhost:${PORT}`);
  });
  return app;
}

// Start server when run directly (not when imported as a module by tests)
if (require.main === module) {
  start().catch(console.error);
}

module.exports = { createApp, start };
