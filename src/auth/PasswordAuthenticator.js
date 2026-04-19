/**
 * PasswordAuthenticator — Password-based login using bcrypt.
 *
 * Implements the Authenticator interface. To add password authentication
 * the user provides username + password, which is verified against
 * the stored bcrypt hash.
 */

const { Authenticator } = require('./Authenticator');

class PasswordAuthenticator extends Authenticator {
  get type() {
    return 'password';
  }

  get label() {
    return 'Password';
  }

  get requiresMfa() {
    return true; // Password alone is insufficient; OTP recommended
  }

  /**
   * @param {{ username: string, password: string }} credentials
   * @param {{ findUserByUsername: function }} ctx
   * @returns {Promise<object|null>}
   */
  async verify({ username, password }, { findUserByUsername }) {
    if (!username || !password) return null;

    const user = findUserByUsername(username);
    if (!user) return null;

    // bcrypt.compare is async; return null on mismatch
    const bcrypt = require('bcryptjs');
    const valid = await bcrypt.compare(password, user.password_hash);
    return valid ? user : null;
  }
}

module.exports = { PasswordAuthenticator };
