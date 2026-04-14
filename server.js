const express = require('express');
const cors = require('cors');
const path = require('path');

const { initDb } = require('./src/db/database');

const authRouter = require('./src/routes/auth');
const passkeyRouter = require('./src/routes/passkey');

async function start() {
  // Initialize DB (creates tables if not exist)
  await initDb();

  const app = express();
  const PORT = process.env.PORT || 3000;

  // Middleware
  app.use(cors());
  app.use(express.json());
  app.use(express.static(path.join(__dirname, 'public')));

  // API routes
  app.use('/api/auth', authRouter);
  app.use('/api/auth/passkey', passkeyRouter);

  // Serve index.html for root
  app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });

  // Catch-all: serve dashboard.html for /dashboard
  app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
  });

  app.listen(PORT, () => {
    console.log(`AuthSystem running at http://localhost:${PORT}`);
  });

  return app;
}

start().catch(console.error);

module.exports = { start };

