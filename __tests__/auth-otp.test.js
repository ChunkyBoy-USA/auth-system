const request = require('supertest');
const express = require('express');
const speakeasy = require('speakeasy');
const authRouter = require('../src/routes/auth');
const models = require('../src/db/models');

// Mock the database models
jest.mock('../src/db/models');

// Mock speakeasy
jest.mock('speakeasy');

describe('OTP Authentication Endpoints', () => {
  let app;
  let mockUser;
  let mockSession;

  beforeEach(() => {
    // Setup Express app with auth router
    app = express();
    app.use(express.json());
    app.use('/api/auth', authRouter);

    // Mock user data
    mockUser = {
      id: 1,
      username: 'testuser',
      password_hash: '$2a$10$abcdefghijklmnopqrstuv',
      subject_id: 1,
      otp_secret: null,
      passkey_credential_id: null,
    };

    mockSession = {
      id: 'session-123',
      user_id: 1,
      device_name: 'Chrome',
      ip_address: '127.0.0.1',
      expires_at: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60,
    };

    // Reset all mocks
    jest.clearAllMocks();

    // Default mock implementations
    models.getSubjectById.mockReturnValue({ id: 1, type: 'individual' });
    models.findUserById.mockReturnValue(mockUser);
    models.findSessionById.mockReturnValue(mockSession);
  });

  describe('POST /api/auth/otp/setup', () => {
    it('should generate OTP secret and return base32 secret and otpauth URL', async () => {
      const mockSecret = {
        base32: 'JBSWY3DPEHPK3PXP',
        otpauth_url: 'otpauth://totp/AuthSystem:testuser?secret=JBSWY3DPEHPK3PXP&issuer=AuthSystem',
      };

      speakeasy.generateSecret.mockReturnValue(mockSecret);
      models.createTempToken.mockReturnValue({
        token: 'setup-token-123',
        user_id: mockUser.id,
        type: 'otp_setup_pending',
        expires_at: Math.floor(Date.now() / 1000) + 600,
        data: mockSecret.base32,
      });

      const response = await request(app)
        .post('/api/auth/otp/setup')
        .set('Authorization', 'Bearer session-123')
        .send();

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('secret', mockSecret.base32);
      expect(response.body).toHaveProperty('otpauthUri', mockSecret.otpauth_url);
      expect(response.body).toHaveProperty('setupToken');
      expect(response.body).toHaveProperty('message');

      expect(speakeasy.generateSecret).toHaveBeenCalledWith({
        name: mockUser.username,
        issuer: 'AuthSystem',
        length: 20,
      });
      expect(models.createTempToken).toHaveBeenCalled();
    });

    it('should return 400 if OTP is already set up', async () => {
      mockUser.otp_secret = 'EXISTING_SECRET';
      models.findUserById.mockReturnValue(mockUser);

      const response = await request(app)
        .post('/api/auth/otp/setup')
        .set('Authorization', 'Bearer session-123')
        .send();

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error', 'OTP already set up');
      expect(speakeasy.generateSecret).not.toHaveBeenCalled();
    });

    it('should require authentication', async () => {
      models.findSessionById.mockReturnValue(null);

      const response = await request(app)
        .post('/api/auth/otp/setup')
        .set('Authorization', 'Bearer invalid-session')
        .send();

      expect(response.status).toBe(401);
    });
  });

  describe('POST /api/auth/otp/enable', () => {
    let mockTempToken;

    beforeEach(() => {
      mockUser.otp_secret = null; // User hasn't enabled OTP yet
      models.findUserById.mockReturnValue(mockUser);

      mockTempToken = {
        token: 'setup-token-123',
        user_id: mockUser.id,
        type: 'otp_setup_pending',
        expires_at: Math.floor(Date.now() / 1000) + 600,
        data: 'JBSWY3DPEHPK3PXP',
      };
    });

    it('should enable OTP when valid code is provided', async () => {
      models.findTempToken.mockReturnValue(mockTempToken);
      speakeasy.totp.verify.mockReturnValue(true);
      models.updateUserOtp.mockReturnValue({ ...mockUser, otp_secret: mockTempToken.data });

      const response = await request(app)
        .post('/api/auth/otp/enable')
        .set('Authorization', 'Bearer session-123')
        .send({ otp_code: '123456', setupToken: 'setup-token-123' });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('success', true);
      expect(response.body).toHaveProperty('message', 'OTP is now enabled');

      expect(speakeasy.totp.verify).toHaveBeenCalledWith({
        secret: mockTempToken.data,
        encoding: 'base32',
        token: '123456',
      });
      expect(models.updateUserOtp).toHaveBeenCalledWith(mockUser.id, mockTempToken.data);
      expect(models.deleteTempToken).toHaveBeenCalledWith('setup-token-123');
    });

    it('should return 401 when invalid OTP code is provided', async () => {
      models.findTempToken.mockReturnValue(mockTempToken);
      speakeasy.totp.verify.mockReturnValue(false);

      const response = await request(app)
        .post('/api/auth/otp/enable')
        .set('Authorization', 'Bearer session-123')
        .send({ otp_code: '000000', setupToken: 'setup-token-123' });

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('error', 'Invalid OTP code — setup not confirmed');
    });

    it('should return 400 if otp_code is missing', async () => {
      const response = await request(app)
        .post('/api/auth/otp/enable')
        .set('Authorization', 'Bearer session-123')
        .send({ setupToken: 'setup-token-123' });

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error', 'otp_code and setupToken are required');
    });

    it('should return 400 if setupToken is missing', async () => {
      const response = await request(app)
        .post('/api/auth/otp/enable')
        .set('Authorization', 'Bearer session-123')
        .send({ otp_code: '123456' });

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error', 'otp_code and setupToken are required');
    });

    it('should return 401 if setup token is invalid', async () => {
      models.findTempToken.mockReturnValue(null);

      const response = await request(app)
        .post('/api/auth/otp/enable')
        .set('Authorization', 'Bearer session-123')
        .send({ otp_code: '123456', setupToken: 'invalid-token' });

      expect(response.status).toBe(401);
      expect(response.body.error).toMatch(/token/i);
    });
  });

  describe('POST /api/auth/mfa/init', () => {
    it('should initiate MFA flow when user has OTP enabled', async () => {
      const bcrypt = require('bcryptjs');
      jest.spyOn(bcrypt, 'compare').mockResolvedValue(true);

      mockUser.otp_secret = 'JBSWY3DPEHPK3PXP';
      models.findUserByUsername.mockReturnValue(mockUser);
      models.createTempToken.mockReturnValue({
        token: 'temp-token-123',
        user_id: mockUser.id,
        type: 'mfa_init',
        expires_at: Math.floor(Date.now() / 1000) + 300,
      });

      const response = await request(app)
        .post('/api/auth/mfa/init')
        .send({ username: 'testuser', password: 'password123' });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('mfa_pending', true);
      expect(response.body).toHaveProperty('temp_token');
      expect(response.body).toHaveProperty('message', 'Password verified. Please enter your OTP code.');

      expect(models.createTempToken).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: mockUser.id,
          type: 'mfa_init',
        })
      );
    });

    it('should return 400 if user has not set up OTP', async () => {
      const bcrypt = require('bcryptjs');
      jest.spyOn(bcrypt, 'compare').mockResolvedValue(true);

      mockUser.otp_secret = null;
      models.findUserByUsername.mockReturnValue(mockUser);

      const response = await request(app)
        .post('/api/auth/mfa/init')
        .send({ username: 'testuser', password: 'password123' });

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error', 'User has not set up OTP');
    });

    it('should return 401 for invalid credentials', async () => {
      const bcrypt = require('bcryptjs');
      jest.spyOn(bcrypt, 'compare').mockResolvedValue(false);

      models.findUserByUsername.mockReturnValue(mockUser);

      const response = await request(app)
        .post('/api/auth/mfa/init')
        .send({ username: 'testuser', password: 'wrongpassword' });

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('error', 'Invalid credentials');
    });

    it('should return 400 if username or password is missing', async () => {
      const response = await request(app)
        .post('/api/auth/mfa/init')
        .send({ username: 'testuser' });

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error', 'username and password are required');
    });
  });

  describe('POST /api/auth/mfa/verify', () => {
    let mockTempToken;

    beforeEach(() => {
      mockUser.otp_secret = 'JBSWY3DPEHPK3PXP';
      models.findUserById.mockReturnValue(mockUser);

      mockTempToken = {
        token: 'temp-token-123',
        user_id: mockUser.id,
        type: 'mfa_init',
        expires_at: Math.floor(Date.now() / 1000) + 300,
      };
      models.findTempToken.mockReturnValue(mockTempToken);
      models.createSession.mockReturnValue(mockSession);
    });

    it('should complete MFA login with valid OTP code', async () => {
      speakeasy.totp.verify.mockReturnValue(true);

      const response = await request(app)
        .post('/api/auth/mfa/verify')
        .send({ temp_token: 'temp-token-123', otp_code: '123456' });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('success', true);
      expect(response.body).toHaveProperty('token', mockSession.id);
      expect(response.body).toHaveProperty('user');
      expect(response.body.user).toHaveProperty('id', mockUser.id);
      expect(response.body.user).toHaveProperty('username', mockUser.username);

      expect(speakeasy.totp.verify).toHaveBeenCalledWith({
        secret: mockUser.otp_secret,
        encoding: 'base32',
        token: '123456',
      });
      expect(models.deleteTempToken).toHaveBeenCalledWith('temp-token-123');
      expect(models.createSession).toHaveBeenCalled();
    });

    it('should return 401 for invalid OTP code', async () => {
      speakeasy.totp.verify.mockReturnValue(false);

      const response = await request(app)
        .post('/api/auth/mfa/verify')
        .send({ temp_token: 'temp-token-123', otp_code: '000000' });

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('error', 'Invalid OTP code');
      expect(models.deleteTempToken).not.toHaveBeenCalled();
    });

    it('should return 401 for expired temp token', async () => {
      mockTempToken.expires_at = Math.floor(Date.now() / 1000) - 100;
      models.findTempToken.mockReturnValue(mockTempToken);

      const response = await request(app)
        .post('/api/auth/mfa/verify')
        .send({ temp_token: 'temp-token-123', otp_code: '123456' });

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('error', 'Temp token expired or invalid');
    });

    it('should return 401 for invalid temp token', async () => {
      models.findTempToken.mockReturnValue(null);

      const response = await request(app)
        .post('/api/auth/mfa/verify')
        .send({ temp_token: 'invalid-token', otp_code: '123456' });

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('error', 'Temp token expired or invalid');
    });

    it('should return 400 if temp_token or otp_code is missing', async () => {
      const response = await request(app)
        .post('/api/auth/mfa/verify')
        .send({ temp_token: 'temp-token-123' });

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error', 'temp_token and otp_code are required');
    });

    it('should return 401 if user does not have OTP set up', async () => {
      mockUser.otp_secret = null;
      models.findUserById.mockReturnValue(mockUser);

      const response = await request(app)
        .post('/api/auth/mfa/verify')
        .send({ temp_token: 'temp-token-123', otp_code: '123456' });

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('error', 'User not found or OTP not set up');
    });
  });

  describe('speakeasy API usage', () => {
    it('should use speakeasy.generateSecret with correct parameters', async () => {
      const mockSecret = {
        base32: 'JBSWY3DPEHPK3PXP',
        otpauth_url: 'otpauth://totp/AuthSystem:testuser?secret=JBSWY3DPEHPK3PXP&issuer=AuthSystem',
      };

      speakeasy.generateSecret.mockReturnValue(mockSecret);
      models.updateUserOtp.mockReturnValue({ ...mockUser, otp_secret: mockSecret.base32 });

      await request(app)
        .post('/api/auth/otp/setup')
        .set('Authorization', 'Bearer session-123')
        .send();

      expect(speakeasy.generateSecret).toHaveBeenCalledWith({
        name: mockUser.username,
        issuer: 'AuthSystem',
        length: 20,
      });
    });

    it('should use speakeasy.totp.verify with correct parameters', async () => {
      const mockTempToken = {
        token: 'setup-token-123',
        user_id: mockUser.id,
        type: 'otp_setup_pending',
        expires_at: Math.floor(Date.now() / 1000) + 600,
        data: 'JBSWY3DPEHPK3PXP',
      };

      models.findTempToken.mockReturnValue(mockTempToken);
      models.findUserById.mockReturnValue(mockUser);
      speakeasy.totp.verify.mockReturnValue(true);

      await request(app)
        .post('/api/auth/otp/enable')
        .set('Authorization', 'Bearer session-123')
        .send({ otp_code: '123456', setupToken: 'setup-token-123' });

      expect(speakeasy.totp.verify).toHaveBeenCalledWith({
        secret: 'JBSWY3DPEHPK3PXP',
        encoding: 'base32',
        token: '123456',
      });
    });
  });
});
