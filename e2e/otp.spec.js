const { test, expect } = require('@playwright/test');

test.describe('OTP Setup and Management', () => {
  let testUsername;
  let testPassword = 'testpass123';

  test.beforeAll(async ({ browser }) => {
    // Create and login a test user
    testUsername = `otpuser${Date.now()}`;
    const page = await browser.newPage();
    await page.goto('/register.html');
    await page.fill('input[name="username"]', testUsername);
    await page.fill('input[name="password"]', testPassword);
    await page.selectOption('select[name="subjectId"]', '1');
    await page.click('button[type="submit"]');
    await page.waitForURL('/');
    await page.close();
  });

  test.beforeEach(async ({ page }) => {
    // Login before each test
    await page.goto('/');
    await page.fill('input[name="username"]', testUsername);
    await page.fill('input[name="password"]', testPassword);
    await page.click('button[type="submit"]');
    await page.waitForURL('/dashboard');
  });

  test('should display OTP setup button when not enabled', async ({ page }) => {
    const setupBtn = page.locator('button:has-text("Set Up OTP")');
    await expect(setupBtn).toBeVisible();
  });

  test('should show QR code when setting up OTP', async ({ page }) => {
    await page.click('button:has-text("Set Up OTP")');

    // Should show QR code
    const qrCode = page.locator('#otpQrCode');
    await expect(qrCode).toBeVisible();

    // Should show input for code
    const codeInput = page.locator('#otpEnableCode');
    await expect(codeInput).toBeVisible();

    // Should show enable button
    const enableBtn = page.locator('button:has-text("Enable OTP")');
    await expect(enableBtn).toBeVisible();
  });

  test('should show error for invalid OTP code', async ({ page }) => {
    await page.click('button:has-text("Set Up OTP")');
    await page.waitForSelector('#otpQrCode');

    // Enter invalid code
    await page.fill('#otpEnableCode', '000000');
    await page.click('button:has-text("Enable OTP")');

    // Should show error message
    await expect(page.locator('#message')).toContainText(/invalid/i);
  });

  test('should show error for empty OTP code', async ({ page }) => {
    await page.click('button:has-text("Set Up OTP")');
    await page.waitForSelector('#otpQrCode');

    // Try to enable without entering code
    await page.click('button:has-text("Enable OTP")');

    // Should show error message
    await expect(page.locator('#message')).toContainText(/6-digit code/i);
  });
});

test.describe('OTP Recovery', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/recover.html');
  });

  test('should display OTP recovery form', async ({ page }) => {
    await expect(page.locator('h1')).toContainText('Reset OTP');
    await expect(page.locator('input[name="username"]')).toBeVisible();
    await expect(page.locator('input[name="password"]')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toContainText(/reset/i);
  });

  test('should show error for missing username', async ({ page }) => {
    await page.fill('input[name="password"]', 'testpass123');
    await page.click('button[type="submit"]');

    await expect(page.locator('#message')).toContainText(/required/i);
  });

  test('should show error for missing password', async ({ page }) => {
    await page.fill('input[name="username"]', 'testuser');
    await page.click('button[type="submit"]');

    await expect(page.locator('#message')).toContainText(/required/i);
  });

  test('should show error for invalid credentials', async ({ page }) => {
    await page.fill('input[name="username"]', 'nonexistentuser');
    await page.fill('input[name="password"]', 'wrongpassword');
    await page.click('button[type="submit"]');

    await expect(page.locator('#message')).toContainText(/invalid credentials/i);
  });

  test('should have link back to login page', async ({ page }) => {
    const loginLink = page.locator('a[href="/"]');
    await expect(loginLink).toBeVisible();
    await expect(loginLink).toContainText(/back to login/i);
  });
});
