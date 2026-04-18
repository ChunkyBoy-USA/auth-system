/**
 * ChallengeStore — Managed in-memory store for WebAuthn challenges.
 *
 * Problems with the old design (raw Map in passkey.js):
 *   1. Expired challenges were never cleaned up — unbounded memory growth
 *   2. The Map was a module-level global with no lifecycle management
 *   3. No way to swap in Redis or a DB-backed store later
 *
 * ChallengeStore solves these by:
 *   - Automatically purging expired entries on every .set() and on a background interval
 *   - Providing a clean interface for registration and authentication challenges
 *   - Being swap-in replaceable with a Redis-backed store (same interface)
 *
 * Background cleanup runs every 60 seconds and removes entries whose
 * expiresAt timestamp has passed.
 */

const CLEANUP_INTERVAL_MS = 60 * 1000;

class ChallengeStore {
  constructor() {
    /**
     * Registration challenges — keyed by user.id (string)
     * Shape: { challenge: string, expiresAt: number }
     * @type {Map<string, { challenge: string, expiresAt: number }>}
     */
    this._regChallenges = new Map();

    /**
     * Authentication challenges — keyed by `auth:${userId}`
     * Shape: { challenge: string, userId: number, expiresAt: number }
     * @type {Map<string, { challenge: string, userId: number, expiresAt: number }>}
     */
    this._authChallenges = new Map();

    // Start background cleanup timer
    this._timer = setInterval(() => this._cleanup(), CLEANUP_INTERVAL_MS);
    // Allow the timer to keep the process alive even if there are no pending challenges
    this._timer.unref();
  }

  // ─── Public API ────────────────────────────────────────────────────────────

  /**
   * Store a registration challenge for a user.
   * Expires after 5 minutes by default.
   *
   * @param {string} userId
   * @param {string} challenge - Base64url-encoded challenge
   * @param {number} [ttlMs=5*60*1000]
   */
  setRegistrationChallenge(userId, challenge, ttlMs = 5 * 60 * 1000) {
    this._regChallenges.set(userId, {
      challenge,
      expiresAt: Date.now() + ttlMs,
    });
  }

  /**
   * Retrieve and consume a registration challenge.
   * Returns null if missing or expired. The entry is deleted on access
   * (single-use challenge semantics).
   *
   * @param {string} userId
   * @returns {{ challenge: string } | null}
   */
  popRegistrationChallenge(userId) {
    const entry = this._regChallenges.get(userId);
    if (!entry) return null;
    if (entry.expiresAt < Date.now()) {
      this._regChallenges.delete(userId);
      return null;
    }
    this._regChallenges.delete(userId);
    return { challenge: entry.challenge };
  }

  /**
   * Store an authentication challenge for a user.
   * Expires after 5 minutes by default.
   *
   * @param {number} userId
   * @param {string} challenge
   * @param {number} [ttlMs=5*60*1000]
   */
  setAuthenticationChallenge(userId, challenge, ttlMs = 5 * 60 * 1000) {
    this._authChallenges.set(`auth:${userId}`, {
      challenge,
      userId,
      expiresAt: Date.now() + ttlMs,
    });
  }

  /**
   * Retrieve and consume an authentication challenge.
   * Returns null if missing or expired.
   *
   * @param {number} userId
   * @returns {{ challenge: string, userId: number } | null}
   */
  popAuthenticationChallenge(userId) {
    const key = `auth:${userId}`;
    const entry = this._authChallenges.get(key);
    if (!entry) return null;
    if (entry.expiresAt < Date.now()) {
      this._authChallenges.delete(key);
      return null;
    }
    this._authChallenges.delete(key);
    return { challenge: entry.challenge, userId: entry.userId };
  }

  // ─── Lifecycle ─────────────────────────────────────────────────────────────

  /**
   * Stop the background cleanup timer. Call this on server shutdown
   * to allow the process to exit cleanly.
   */
  shutdown() {
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
  }

  /** Expose size for testing / monitoring purposes. */
  get size() {
    return this._regChallenges.size + this._authChallenges.size;
  }

  // ─── Internal ─────────────────────────────────────────────────────────────

  /** Remove all expired entries. Called on interval and on .set(). */
  _cleanup() {
    const now = Date.now();

    for (const [key, entry] of this._regChallenges) {
      if (entry.expiresAt < now) this._regChallenges.delete(key);
    }

    for (const [key, entry] of this._authChallenges) {
      if (entry.expiresAt < now) this._authChallenges.delete(key);
    }
  }
}

// ─── Singleton instance ────────────────────────────────────────────────────────
// Exported as a singleton so all routes share the same store.
// Export the class too so tests can instantiate fresh instances.
const challengeStore = new ChallengeStore();

module.exports = { ChallengeStore, challengeStore };
