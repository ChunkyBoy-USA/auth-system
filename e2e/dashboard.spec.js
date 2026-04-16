const { test, expect } = require('@playwright/test');

test.describe('Dashboard and Session Management', () => {
  let testUsername;
  let testPassword = 'testpass123';

  test.beforeAll(async ({ browser }) => {
    // Create and login a test user
    testUsername = `dashuser${Date.now()}`;
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

  test('should display user profile information', async ({ page }) => {
    await expect(page.locator('h2')).toContainText('Profile');
    await expect(page.locator('#userUsername')).toContainText(testUsername);
    await expect(page.locator('#userSubjectType')).toContainText('member');
    await expect(page.locator('#userHasOtp')).toContainText(/no/i);
    await expect(page.locator('#userHasPasskey')).toContainText(/no/i);
  });

  test('should display active sessions', async ({ page }) => {
    await expect(page.locator('h2')).toContainText('Active Sessions');

    const sessionsList = page.locator('#sessionsList');
    await expect(sessionsList).toBeVisible();

    // Should have at least one session (current)
    const currentSession = page.locator('.session-item.current');
    await expect(currentSession).toBeVisible();
    await expect(currentSession.locator('.badge')).toContainText('Current');
  });

  test('should display security settings', async ({ page }) => {
    await expect(page.locator('h2')).toContainText('Security Settings');

    // OTP section
    await expect(page.locator('h3')).toContainText('OTP');
    await expect(page.locator('button')).toContainText('Set Up OTP');

    // Passkey section
    await expect(page.locator('h3')).toContainText('Passkey');
  });

  test('should logout successfully', async ({ page }) => {
    await page.click('button:has-text("Logout")');

    // Should redirect to login page
    await expect(page).toHaveURL('/');

    // Try to access dashboard - should redirect back to login
    await page.goto('/dashboard');
    await expect(page).toHaveURL('/');
  });

  test('should show logout all devices button', async ({ page }) => {
    const logoutAllBtn = page.locator('button:has-text("Logout All Devices")');
    await expect(logoutAllBtn).toBeVisible();
  });

  test('should logout all devices with confirmation', async ({ page }) => {
    // Setup dialog handler
    page.on('dialog', dialog => dialog.accept());

    await page.click('button:has-text("Logout All Devices")');

    // Should redirect to login page
    await expect(page).toHaveURL('/');
  });

  test('should not allow access to dashboard without login', async ({ page }) => {
    // Logout first
    await page.click('button:has-text("Logout")');
    await expect(page).toHaveURL('/');

    // Try to access dashboard directly
    await page.goto('/dashboard');
    await expect(page).toHaveURL('/');
  });
});
