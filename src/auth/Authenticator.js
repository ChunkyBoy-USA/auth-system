/**
 * Authenticator — Interface for all authentication methods.
 *
 * Every login mechanism (Password, OTP, Passkey, OAuth, Magic Link, etc.)
 * implements this interface. AuthService iterates over registered authenticators
 * without needing to know the details of each method (Dependency Inversion Principle).
 *
 * Adding a new login method requires only:
 *   1. Create a new <Method>Authenticator.js file
 *   2. Register it with AuthService
 * No changes to routes, AuthService, or existing authenticators.
 *
 * Interface contract:
 *   - type        {string}  Unique identifier, e.g. 'password'
 *   - label       {string}  Human-readable name, e.g. 'Password'
 *   - requiresMfa {boolean} Whether this method alone is insufficient (MFA is needed too)
 *   - verify(credentials, ctx) → Promise<User|null>
 *       ctx contains { findUserByUsername, findUserById } for lookups,
 *       plus anything else the method needs (challengeStore, etc.)
 */

class Authenticator {
  /**
   * @returns {string} Unique identifier for this authenticator
   */
  get type() {
    throw new Error('Authenticator subclasses must implement the "type" getter');
  }

  /**
   * @returns {string} Human-readable label for UI display
   */
  get label() {
    throw new Error('Authenticator subclasses must implement the "label" getter');
  }

  /**
   * @returns {boolean} True if this method alone is insufficient (MFA recommended)
   */
  get requiresMfa() {
    return false;
  }

  /**
   * Verify credentials and return the authenticated user, or null on failure.
   *
   * @param {object} credentials - Method-specific credentials (e.g. { username, password })
   * @param {object} ctx        - Context helpers (findUserByUsername, findUserById, ...)
   * @returns {Promise<object|null>} User object on success, null on failure
   */
  async verify(credentials, ctx) {
    throw new Error(`${this.constructor.name} must implement verify(credentials, ctx)`);
  }
}

module.exports = { Authenticator };
