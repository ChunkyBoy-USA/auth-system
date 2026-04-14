const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

/**
 * Generate a new TOTP secret + QR code data URL for a user.
 * Mirrors POST /api/auth/otp/setup
 */
async function generateOtpSetup(username) {
  const secret = speakeasy.generateSecret({
    name: username,
    issuer: 'AuthSystem',
    length: 20,
  });
  const qrCodeDataUrl = await QRCode.toDataURL(secret.otpauth_url);
  return {
    secret: secret.base32,
    otpauthUri: secret.otpauth_url,
    qrCodeDataUrl,
  };
}

/**
 * Verify a TOTP token against a base32 secret.
 * Mirrors POST /api/auth/otp/enable
 */
function verifyOtp(secret, token) {
  return speakeasy.totp.verify({
    secret,
    encoding: 'base32',
    token,
  });
}

/**
 * Generate a TOTP token for a given base32 secret.
 * Used by tests to produce valid codes.
 */
function generateOtpToken(secret) {
  return speakeasy.totp({ secret, encoding: 'base32' });
}

/**
 * Verify that a QR code data URL is a valid PNG data URI.
 */
function isValidQrDataUrl(dataUrl) {
  return (
    typeof dataUrl === 'string' &&
    dataUrl.startsWith('data:image/png;base64,') &&
    dataUrl.length > 100
  );
}

/**
 * Verify that an otpauth URI has the expected format.
 */
function isValidOtpauthUri(uri) {
  // speakeasy format: otpauth://totp/<username>?secret=<base32>
  return (
    typeof uri === 'string' &&
    uri.startsWith('otpauth://totp/') &&
    uri.includes('secret=')
  );
}

module.exports = {
  generateOtpSetup,
  verifyOtp,
  generateOtpToken,
  isValidQrDataUrl,
  isValidOtpauthUri,
};
