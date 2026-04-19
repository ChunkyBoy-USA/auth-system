/**
 * OtpAuthenticator — TOTP-based login using speakeasy.
 *
 * Implements the Authenticator interface. The user provides a username
 * and a TOTP code from their authenticator app (Google Authenticator, Authy, etc.).
 */

const speakeasy = require('speakeasy');
const { Authenticator } = require('./Authenticator');

class OtpAuthenticator extends Authenticator {
  get type() {
    return 'otp';
  }

  get label() {
    return 'Authenticator App (TOTP)';
  }

  get requiresMfa() {
    return true;
  }

  /**
   * @param {{ username: string, otp_code: string }} credentials
   * @param {{ findUserByUsername: function }} ctx
   * @returns {object|null} User on success, null on failure
   */
  verify({ username, otp_code }, { findUserByUsername }) {
    if (!username || !otp_code) return null;

    const user = findUserByUsername(username);
    if (!user) return null;

    if (!user.otp_secret) return null;

    const valid = speakeasy.totp.verify({
      secret: user.otp_secret,
      encoding: 'base32',
      token: otp_code,
    });

    return valid ? user : null;
  }
}

module.exports = { OtpAuthenticator };
