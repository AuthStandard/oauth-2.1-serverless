/**
 * SES-03: Bad Password
 *
 * Tests that the login form correctly rejects invalid passwords
 * and provides appropriate feedback without leaking information.
 */

import { test, expect } from '@playwright/test';
import {
  generatePKCE,
  generateState,
  buildAuthorizationUrl,
  TEST_CLIENTS,
  TEST_USERS,
} from '../../support/browser';

test.describe('SES-03: Bad Password', () => {
  test('should reject login with incorrect password', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.public;
    const user = TEST_USERS.standard;

    // Navigate to authorize to get redirected to login
    const authUrl = buildAuthorizationUrl({
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      scope: 'openid profile',
      state,
      codeChallenge: pkce.challenge,
      codeChallengeMethod: 'S256',
    });

    await page.goto(authUrl);

    // Wait for login form
    await page.waitForSelector('input[name="email"], input[type="email"]');

    // Enter valid email but wrong password
    await page.fill('input[name="email"], input[type="email"]', user.email);
    await page.fill('input[name="password"], input[type="password"]', 'WrongPassword123!');

    // Submit form
    await page.click('button[type="submit"], input[type="submit"]');

    // Should stay on login page with error message
    // Wait for either error message or page reload
    await page.waitForLoadState('networkidle');

    // Should still be on login page (not redirected to callback)
    const currentUrl = page.url();
    expect(currentUrl).not.toContain(client.redirect_uris[0]);

    // Should show some form of error indication
    // Look for common error patterns
    const pageContent = await page.content();
    const hasErrorIndication =
      pageContent.toLowerCase().includes('invalid') ||
      pageContent.toLowerCase().includes('incorrect') ||
      pageContent.toLowerCase().includes('error') ||
      pageContent.toLowerCase().includes('failed') ||
      (await page.locator('[class*="error"], [class*="alert"], [role="alert"]').count()) > 0;

    expect(hasErrorIndication).toBe(true);
  });

  test('should not reveal whether email exists', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.public;

    const authUrl = buildAuthorizationUrl({
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      scope: 'openid profile',
      state,
      codeChallenge: pkce.challenge,
      codeChallengeMethod: 'S256',
    });

    await page.goto(authUrl);
    await page.waitForSelector('input[name="email"], input[type="email"]');

    // Try with non-existent email
    await page.fill('input[name="email"], input[type="email"]', 'nonexistent@example.com');
    await page.fill('input[name="password"], input[type="password"]', 'SomePassword123!');
    await page.click('button[type="submit"], input[type="submit"]');

    await page.waitForLoadState('networkidle');

    // Get error message for non-existent user
    const nonExistentContent = await page.content();

    // Navigate back to login
    await page.goto(authUrl);
    await page.waitForSelector('input[name="email"], input[type="email"]');

    // Try with existing email but wrong password
    await page.fill('input[name="email"], input[type="email"]', TEST_USERS.standard.email);
    await page.fill('input[name="password"], input[type="password"]', 'WrongPassword123!');
    await page.click('button[type="submit"], input[type="submit"]');

    await page.waitForLoadState('networkidle');

    // Get error message for existing user with wrong password
    const existingContent = await page.content();

    // Error messages should be similar (not reveal user existence)
    // This is a basic check - both should show generic "invalid credentials" type message
    // rather than "user not found" vs "wrong password"
    const nonExistentHasUserNotFound =
      nonExistentContent.toLowerCase().includes('user not found') ||
      nonExistentContent.toLowerCase().includes('no account') ||
      nonExistentContent.toLowerCase().includes('email not registered');

    const existingHasWrongPassword =
      existingContent.toLowerCase().includes('wrong password') ||
      existingContent.toLowerCase().includes('incorrect password');

    // Should NOT reveal that user doesn't exist
    expect(nonExistentHasUserNotFound).toBe(false);
    // Should NOT reveal that password is wrong (vs user not found)
    expect(existingHasWrongPassword).toBe(false);
  });

  test('should allow retry after failed login', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.public;
    const user = TEST_USERS.standard;

    const authUrl = buildAuthorizationUrl({
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      scope: 'openid profile',
      state,
      codeChallenge: pkce.challenge,
      codeChallengeMethod: 'S256',
    });

    await page.goto(authUrl);
    await page.waitForSelector('input[name="email"], input[type="email"]');

    // First attempt - wrong password
    await page.fill('input[name="email"], input[type="email"]', user.email);
    await page.fill('input[name="password"], input[type="password"]', 'WrongPassword123!');
    await page.click('button[type="submit"], input[type="submit"]');

    await page.waitForLoadState('networkidle');

    // Second attempt - correct password
    await page.fill('input[name="email"], input[type="email"]', user.email);
    await page.fill('input[name="password"], input[type="password"]', user.password);
    await page.click('button[type="submit"], input[type="submit"]');

    // Should succeed and redirect to callback
    await page.waitForURL(url => url.href.startsWith(client.redirect_uris[0]), {
      timeout: 30000,
    });

    expect(page.url()).toContain('code=');
  });
});
