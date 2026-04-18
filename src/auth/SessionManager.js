/**
 * SessionManager — Centralized session lifecycle management.
 *
 * Previously session creation was duplicated across auth.js and passkey.js
 * with slightly different logic. SessionManager consolidates all session
 * operations in one place (Single Responsibility Principle):
 *   - Create a session with device/IP metadata
 *   - Find and validate sessions (including expiry)
 *   - Touch last-active timestamp
 *   - Delete individual sessions
 *   - Delete all sessions for a user
 *
 * This also makes swapping the storage backend (e.g. moving from sql.js
 * to Redis) a single-file change.
 */

const { v4: uuidv4 } = require('uuid');
const {
  createSession,
  findSessionById,
  findSessionsByUserId,
  touchSession,
  deleteSession,
  deleteAllSessionsForUser,
} = require('../db/models');

const DEFAULT_SESSION_TTL_SECONDS = 7 * 24 * 60 * 60; // 7 days

/**
 * Parse device and IP from an Express request.
 * Extracted here so it's defined once and reused by AuthService.
 *
 * @param {import('express').Request} req
 * @returns {{ deviceName: string, ipAddress: string }}
 */
function parseDevice(req) {
  const ua = req?.headers?.['user-agent'] || 'Unknown Device';
  let deviceName = 'Unknown Device';
  if (ua.includes('Edg/')) deviceName = 'Edge';
  else if (ua.includes('Chrome')) deviceName = 'Chrome';
  else if (ua.includes('Firefox')) deviceName = 'Firefox';
  else if (ua.includes('Safari') && !ua.includes('Chrome')) deviceName = 'Safari';
  else if (ua.includes('Postman')) deviceName = 'Postman';
  else deviceName = ua.slice(0, 40);

  const ipAddress = req?.ip || req?.connection?.remoteAddress || '0.0.0.0';
  return { deviceName, ipAddress };
}

class SessionManager {
  /**
   * Create a new session for a user.
   *
   * @param {object} user   - User row from the database
   * @param {object} req    - Express request (used for device/IP metadata)
   * @param {number} [ttlSeconds=DEFAULT_SESSION_TTL_SECONDS]
   * @returns {object} The created session row
   */
  createSession(user, req, ttlSeconds = DEFAULT_SESSION_TTL_SECONDS) {
    const { deviceName, ipAddress } = parseDevice(req);
    const now = Math.floor(Date.now() / 1000);
    return createSession({
      id: uuidv4(),
      userId: user.id,
      deviceName,
      ipAddress,
      expiresAt: now + ttlSeconds,
    });
  }

  /**
   * Find and validate a session by ID. Returns null if the session
   * is missing or expired.
   *
   * @param {string} sessionId
   * @returns {object|null}
   */
  findValidSession(sessionId) {
    if (!sessionId) return null;
    const session = findSessionById(sessionId);
    if (!session) return null;
    const now = Math.floor(Date.now() / 1000);
    if (session.expires_at < now) return null;
    return session;
  }

  /**
   * Touch a session to update its last_active_at timestamp.
   *
   * @param {string} sessionId
   */
  touch(sessionId) {
    touchSession(sessionId);
  }

  /**
   * Delete a specific session.
   *
   * @param {string} sessionId
   */
  delete(sessionId) {
    deleteSession(sessionId);
  }

  /**
   * Delete all sessions for a user.
   *
   * @param {number} userId
   */
  deleteAllForUser(userId) {
    deleteAllSessionsForUser(userId);
  }

  /**
   * List all sessions for a user with enriched metadata.
   *
   * @param {number} userId
   * @param {string} [currentSessionId] - Mark this session as "current" in the response
   * @returns {object[]}
   */
  listForUser(userId, currentSessionId) {
    const sessions = findSessionsByUserId(userId);
    const now = Math.floor(Date.now() / 1000);
    return sessions.map((s) => ({
      id: s.id,
      deviceName: s.device_name,
      ipAddress: s.ip_address,
      createdAt: s.created_at,
      expiresAt: s.expires_at,
      lastActiveAt: s.last_active_at,
      isCurrent: currentSessionId ? s.id === currentSessionId : false,
      isExpired: s.expires_at < now,
    }));
  }
}

module.exports = { SessionManager, parseDevice };
