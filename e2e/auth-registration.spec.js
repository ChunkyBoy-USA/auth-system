const { test, expect } = require('@playwright/test');

test.describe('User Registration', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/register.html');
  });

  test('should display registration form', async ({ page }) => {
    await expect(page.locator('h1')).toContainText('Create Account');
    await expect(page.locator('input[name="username"]')).toBeVisible();
    await expect(page.locator('input[name="password"]')).toBeVisible();
    await expect(page.locator('select[name="subjectId"]')).toBeVisible();
  });

  test('should show error for missing username', async ({ page }) => {
    await page.fill('input[name="password"]', 'testpass123');
    await page.selectOption('select[name="subjectId"]', '1');
    await page.click('button[type="submit"]');

    await expect(page.locator('#message')).toContainText(/required/i);
  });

  test('should show error for missing password', async ({ page }) => {
    await page.fill('input[name="username"]', 'testuser');
    await page.selectOption('select[name="subjectId"]', '1');
    await page.click('button[type="submit"]');

    await expect(page.locator('#message')).toContainText(/required/i);
  });

  test('should successfully register a new user', async ({ page }) => {
    const username = `e2euser${Date.now()}`;

    await page.fill('input[name="username"]', username);
    await page.fill('input[name="password"]', 'testpass123');
    await page.selectOption('select[name="subjectId"]', '1');
    await page.click('button[type="submit"]');

    // Should redirect to login page
    await expect(page).toHaveURL('/');
    await expect(page.locator('#message')).toContainText(/registered successfully/i);
  });

  test('should show error for duplicate username', async ({ page }) => {
    const username = `duplicate${Date.now()}`;

    // Register first time
    await page.fill('input[name="username"]', username);
    await page.fill('input[name="password"]', 'testpass123');
    await page.selectOption('select[name="subjectId"]', '1');
    await page.click('button[type="submit"]');

    await page.waitForURL('/');

    // Try to register again with same username
    await page.goto('/register.html');
    await page.fill('input[name="username"]', username);
    await page.fill('input[name="password"]', 'testpass123');
    await page.selectOption('select[name="subjectId"]', '1');
    await page.click('button[type="submit"]');

    await expect(page.locator('#message')).toContainText(/already taken/i);
  });

  test('should register different subject types', async ({ page }) => {
    const username = `staff${Date.now()}`;

    await page.fill('input[name="username"]', username);
    await page.fill('input[name="password"]', 'testpass123');
    await page.selectOption('select[name="subjectId"]', '2'); // Community Staff
    await page.click('button[type="submit"]');

    await expect(page).toHaveURL('/');
    await expect(page.locator('#message')).toContainText(/registered successfully/i);
  });
});
