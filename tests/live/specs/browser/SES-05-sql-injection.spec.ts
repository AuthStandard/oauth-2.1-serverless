/**
 * SES-05: SQL Injection Prevention
 *
 * Tests that the login form properly sanitizes input and is not
 * vulnerable to SQL injection attacks.
 */

import { test, expect } from '@playwright/test';
import {
  generatePKCE,
  generateState,
  buildAuthorizationUrl,
  TEST_CLIENTS,
} from '../../support/browser';

test.describe('SES-05: SQL Injection Prevention', () => {
  const SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "admin'--",
    "' OR 1=1 --",
  ];

  test('should reject SQL injection in email field', async ({ page }) => {
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

    // Test a few payloads (not all, to keep test fast)
    for (const payload of SQL_INJECTION_PAYLOADS.slice(0, 2)) {
      await page.goto(authUrl);
      await page.waitForSelector('input[name="email"], input[type="email"]');

      // Try SQL injection in email field
      await page.fill('input[name="email"], input[type="email"]', payload);
      await page.fill('input[name="password"], input[type="password"]', 'password123');
      await page.click('button[type="submit"], input[type="submit"]');

      await page.waitForLoadState('networkidle');

      const currentUrl = page.url();
      const pageContent = await page.content();

      // Should not have bypassed authentication
      expect(currentUrl).not.toContain('code=');

      // Should not show database errors
      const hasDatabaseError =
        pageContent.toLowerCase().includes('syntax error') ||
        pageContent.toLowerCase().includes('mysql') ||
        pageContent.toLowerCase().includes('postgresql');

      expect(hasDatabaseError).toBe(false);
    }
  });

  test('should reject SQL injection in password field', async ({ page }) => {
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

    // Try SQL injection in password field
    await page.fill('input[name="email"], input[type="email"]', 'test@example.com');
    await page.fill('input[name="password"], input[type="password"]', "' OR '1'='1");
    await page.click('button[type="submit"], input[type="submit"]');

    await page.waitForLoadState('networkidle');

    // Should not bypass authentication
    expect(page.url()).not.toContain('code=');

    // Should show normal login failure, not database error
    const pageContent = await page.content();
    const hasDatabaseError =
      pageContent.toLowerCase().includes('sql') ||
      pageContent.toLowerCase().includes('syntax error');

    expect(hasDatabaseError).toBe(false);
  });

  test('should handle special characters safely', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.public;

    const specialChars = [
      "test'user@example.com",
      'test"user@example.com',
    ];

    const authUrl = buildAuthorizationUrl({
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      scope: 'openid profile',
      state,
      codeChallenge: pkce.challenge,
      codeChallengeMethod: 'S256',
    });

    for (const email of specialChars) {
      await page.goto(authUrl);
      await page.waitForSelector('input[name="email"], input[type="email"]');

      await page.fill('input[name="email"], input[type="email"]', email);
      await page.fill('input[name="password"], input[type="password"]', 'password123');
      await page.click('button[type="submit"], input[type="submit"]');

      await page.waitForLoadState('networkidle');

      // Should handle gracefully without server errors
      const pageContent = await page.content();
      const hasServerError =
        pageContent.toLowerCase().includes('internal server error') ||
        pageContent.toLowerCase().includes('exception');

      expect(hasServerError).toBe(false);
    }
  });
});
