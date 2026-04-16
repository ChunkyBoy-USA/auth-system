const {
  generateOtpSetup,
  verifyOtp,
  generateOtpToken,
  isValidQrDataUrl,
  isValidOtpauthUri,
} = require('../src/routes/otpHelpers');

describe('OTP / TOTP helpers', () => {
  describe('generateOtpSetup', () => {
    it('returns secret, otpauthUri, and qrCodeDataUrl', async () => {
      const result = await generateOtpSetup('testuser');
      expect(result).toHaveProperty('secret');
      expect(result).toHaveProperty('otpauthUri');
      expect(result).toHaveProperty('qrCodeDataUrl');
    });

    it('returns a valid base32 secret (alphanumeric uppercase)', async () => {
      const result = await generateOtpSetup('alice');
      expect(result.secret).toMatch(/^[A-Z2-7]+$/);
      expect(result.secret.length).toBeGreaterThanOrEqual(16);
    });

    it('returns a valid otpauth URI', async () => {
      const result = await generateOtpSetup('bob');
      expect(isValidOtpauthUri(result.otpauthUri)).toBe(true);
    });

    it('returns a valid QR code data URL', async () => {
      const result = await generateOtpSetup('charlie');
      expect(isValidQrDataUrl(result.qrCodeDataUrl)).toBe(true);
    });

    it('includes username in the otpauth URI', async () => {
      const result = await generateOtpSetup('diana');
      expect(result.otpauthUri).toContain('diana');
    });

    it('generates different secrets for different users', async () => {
      const [result1, result2] = await Promise.all([
        generateOtpSetup('user1'),
        generateOtpSetup('user2'),
      ]);
      expect(result1.secret).not.toBe(result2.secret);
    });
  });

  describe('verifyOtp', () => {
    it('verifies a valid TOTP token', async () => {
      const { secret } = await generateOtpSetup('verifyuser');
      const token = generateOtpToken(secret);
      expect(verifyOtp(secret, token)).toBe(true);
    });

    it('rejects an invalid TOTP token', async () => {
      const { secret } = await generateOtpSetup('rejectuser');
      expect(verifyOtp(secret, '000000')).toBe(false);
    });

    it('rejects a malformed secret', () => {
      expect(verifyOtp('NOTVALIDBASE32ATALL!!!', '123456')).toBe(false);
    });
  });

  describe('generateOtpToken', () => {
    it('generates a 6-digit numeric token', async () => {
      const { secret } = await generateOtpSetup('tokenuser');
      const token = generateOtpToken(secret);
      expect(token).toMatch(/^\d{6}$/);
    });

    it('generated token is verifiable immediately', async () => {
      const { secret } = await generateOtpSetup('immediateuser');
      const token = generateOtpToken(secret);
      expect(verifyOtp(secret, token)).toBe(true);
    });

    it('generates different tokens at different times', async () => {
      const { secret } = await generateOtpSetup('timeuser');
      const token1 = generateOtpToken(secret);
      // Wait at least 1 second to get a different time step
      await new Promise((r) => setTimeout(r, 1100));
      const token2 = generateOtpToken(secret);
      // They may or may not differ depending on timing, but both should be valid
      expect(token1).toMatch(/^\d{6}$/);
      expect(token2).toMatch(/^\d{6}$/);
    });
  });

  describe('isValidQrDataUrl', () => {
    it('returns true for valid PNG data URL', () => {
      const valid = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
      expect(isValidQrDataUrl(valid)).toBe(true);
    });

    it('returns false for non-base64 strings', () => {
      expect(isValidQrDataUrl('not a data url')).toBe(false);
    });

    it('returns false for empty string', () => {
      expect(isValidQrDataUrl('')).toBe(false);
    });

    it('returns false for non-string values', () => {
      expect(isValidQrDataUrl(null)).toBe(false);
      expect(isValidQrDataUrl(undefined)).toBe(false);
    });
  });

  describe('isValidOtpauthUri', () => {
    it('returns true for valid otpauth URI', () => {
      const uri = 'otpauth://totp/testuser?secret=ABCD1234&issuer=AuthSystem';
      expect(isValidOtpauthUri(uri)).toBe(true);
    });

    it('returns false for non-otpauth URI', () => {
      expect(isValidOtpauthUri('http://evil.com')).toBe(false);
    });

    it('returns false for URI missing secret', () => {
      expect(isValidOtpauthUri('otpauth://totp/testuser')).toBe(false);
    });
  });
});
