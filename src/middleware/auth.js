const { findSessionById, findUserById, touchSession } = require('../db/models');

// Attach user + session to req from Authorization: Bearer <token> header
function authMiddleware(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: 'Missing authorization token' });
  }

  const now = Math.floor(Date.now() / 1000);
  const session = findSessionById(token);

  if (!session || session.expires_at < now) {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }

  const user = findUserById(session.user_id);
  if (!user) {
    return res.status(401).json({ error: 'User not found' });
  }

  // Update last active timestamp
  touchSession(token);

  req.user = user;
  req.session = session;
  next();
}

module.exports = { authMiddleware };
