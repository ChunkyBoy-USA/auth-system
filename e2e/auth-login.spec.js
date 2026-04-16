const { test, expect } = require('@playwright/test');

test.describe('User Login', () => {
  let testUsername;
  let testPassword = 'testpass123';

  test.beforeAll(async ({ browser }) => {
    // Create a test user before running login tests
    testUsername = `loginuser${Date.now()}`;
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
    await page.goto('/');
  });

  test('should display login form', async ({ page }) => {
    await expect(page.locator('h1')).toContainText('AuthSystem');
    await expect(page.locator('input[name="username"]')).toBeVisible();
    await expect(page.locator('input[name="password"]')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toContainText(/login/i);
  });

  test('should show error for missing username', async ({ page }) => {
    await page.fill('input[name="password"]', testPassword);
    await page.click('button[type="submit"]');

    await expect(page.locator('#message')).toContainText(/required/i);
  });

  test('should show error for missing password', async ({ page }) => {
    await page.fill('input[name="username"]', testUsername);
    await page.click('button[type="submit"]');

    await expect(page.locator('#message')).toContainText(/required/i);
  });

  test('should show error for invalid credentials', async ({ page }) => {
    await page.fill('input[name="username"]', 'nonexistentuser');
    await page.fill('input[name="password"]', 'wrongpassword');
    await page.click('button[type="submit"]');

    await expect(page.locator('#message')).toContainText(/invalid credentials/i);
  });

  test('should show error for wrong password', async ({ page }) => {
    await page.fill('input[name="username"]', testUsername);
    await page.fill('input[name="password"]', 'wrongpassword');
    await page.click('button[type="submit"]');

    await expect(page.locator('#message')).toContainText(/invalid credentials/i);
  });

  test('should successfully login with correct credentials', async ({ page }) => {
    await page.fill('input[name="username"]', testUsername);
    await page.fill('input[name="password"]', testPassword);
    await page.click('button[type="submit"]');

    // Should redirect to dashboard
    await expect(page).toHaveURL('/dashboard');
    await expect(page.locator('#navUsername')).toContainText(testUsername);
  });

  test('should have link to registration page', async ({ page }) => {
    const registerLink = page.locator('a[href="/register.html"]');
    await expect(registerLink).toBeVisible();
    await expect(registerLink).toContainText(/create account/i);
  });
});
