# End-to-End UI Tests

This directory contains Playwright-based end-to-end tests for the AuthSystem UI.

## Test Coverage

### Authentication Tests
- **auth-registration.spec.js** - User registration flows
  - Form validation (missing fields)
  - Successful registration
  - Duplicate username handling
  - Different subject types

- **auth-login.spec.js** - User login flows
  - Form validation
  - Invalid credentials handling
  - Successful login
  - Navigation to dashboard

### Dashboard Tests
- **dashboard.spec.js** - Dashboard and session management
  - Profile information display
  - Active sessions list
  - Security settings
  - Logout functionality
  - Logout all devices
  - Protected route access

### Security Tests
- **otp.spec.js** - OTP setup and recovery
  - OTP setup flow
  - QR code display
  - Code validation
  - OTP recovery form

## Running Tests

### Run all UI tests (headless)
```bash
npm run test:ui
```

### Run tests with browser visible
```bash
npm run test:ui:headed
```

### Debug tests with Playwright Inspector
```bash
npm run test:ui:debug
```

### Run specific test file
```bash
npx playwright test e2e/auth-login.spec.js
```

### Run tests in specific browser
```bash
npx playwright test --project=chromium
```

## Test Configuration

Tests are configured in `playwright.config.js`:
- Base URL: `http://localhost:3000`
- Browser: Chromium (Desktop Chrome)
- Workers: 1 (sequential execution to avoid DB conflicts)
- Auto-starts server before tests
- Screenshots on failure
- Trace on first retry

## Writing New Tests

1. Create a new `.spec.js` file in the `e2e/` directory
2. Import Playwright test utilities:
   ```javascript
   const { test, expect } = require('@playwright/test');
   ```
3. Use `test.describe()` to group related tests
4. Use `test.beforeEach()` for common setup
5. Write assertions with `expect()`

## Best Practices

- Use unique usernames with timestamps to avoid conflicts
- Clean up test data in `beforeAll` or `afterAll` hooks
- Use page object pattern for complex flows
- Keep tests independent and idempotent
- Use meaningful test descriptions
- Add comments for complex interactions

## CI/CD Integration

To run tests in CI:
```bash
npx playwright install --with-deps chromium
npm run test:ui
```

## Troubleshooting

### Tests timing out
- Increase timeout in `playwright.config.js`
- Check if server is starting correctly
- Verify database is accessible

### Flaky tests
- Add explicit waits: `await page.waitForSelector()`
- Use `waitForURL()` for navigation
- Check for race conditions

### Browser not found
Run: `npx playwright install chromium`
