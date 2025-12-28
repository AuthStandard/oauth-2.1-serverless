/**
 * AUT-18: Prompt None (Logged In)
 *
 * Tests that prompt=none returns an authorization code when the user
 * already has an active session (silent authentication).
 *
 * Per OIDC Core 1.0 Section 3.1.2.1:
 * "If the End-User is already authenticated, the Authorization Server
 * MUST NOT display any authentication or consent UI."
 */

import { test, expect } from '@playwright/test';
import {
  generatePKCE,
  generateState,
  buildAuthorizationUrl,
  login,
  extractCodeFromUrl,
  extractErrorFromUrl,
  TEST_CLIENTS,
  TEST_USERS,
} from '../../support/browser';

test.describe('AUT-18: Prompt None (Logged In)', () => {
  test('should return code silently when user has active session', async ({ page }) => {
    const client = TEST_CLIENTS.public;
    const user = TEST_USERS.standard;

    // First, establish a session by logging in normally
    const pkce1 = generatePKCE();
    const state1 = generateState();

    const authUrl1 = buildAuthorizationUrl({
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      scope: 'openid profile',
      state: state1,
      codeChallenge: pkce1.challenge,
      codeChallengeMethod: 'S256',
    });

    await page.goto(authUrl1);
    await login(page, user.email, user.password);

    // Wait for redirect with code
    await page.waitForURL(url => url.href.startsWith(client.redirect_uris[0]), {
      timeout: 30000,
    });

    const firstCode = extractCodeFromUrl(page.url());
    expect(firstCode).toBeTruthy();

    // Now try silent auth with prompt=none
    // The session cookie should be set from the first login
    const pkce2 = generatePKCE();
    const state2 = generateState();

    const silentAuthUrl = buildAuthorizationUrl({
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      scope: 'openid profile',
      state: state2,
      codeChallenge: pkce2.challenge,
      codeChallengeMethod: 'S256',
      prompt: 'none',
    });

    await page.goto(silentAuthUrl);

    // Should redirect directly to callback (no login UI)
    await page.waitForURL(url => url.href.startsWith(client.redirect_uris[0]), {
      timeout: 10000,
    });

    // Per OIDC Core 1.0, with an active session, prompt=none MUST return a code
    const code = extractCodeFromUrl(page.url());
    expect(code).toBeTruthy();
    expect(code).not.toBe(firstCode); // Should be a new code
  });

  test('should preserve state in silent auth response', async ({ page }) => {
    const client = TEST_CLIENTS.public;
    const user = TEST_USERS.standard;

    // Establish session
    const pkce1 = generatePKCE();
    await page.goto(buildAuthorizationUrl({
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      scope: 'openid',
      state: generateState(),
      codeChallenge: pkce1.challenge,
      codeChallengeMethod: 'S256',
    }));

    await login(page, user.email, user.password);
    await page.waitForURL(url => url.href.startsWith(client.redirect_uris[0]));

    // Silent auth with specific state
    const pkce2 = generatePKCE();
    const silentState = 'silent-auth-state-12345';

    await page.goto(buildAuthorizationUrl({
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      scope: 'openid',
      state: silentState,
      codeChallenge: pkce2.challenge,
      codeChallengeMethod: 'S256',
      prompt: 'none',
    }));

    await page.waitForURL(url => url.href.startsWith(client.redirect_uris[0]));

    const finalUrl = new URL(page.url());
    expect(finalUrl.searchParams.get('state')).toBe(silentState);
    expect(finalUrl.searchParams.get('code')).toBeTruthy();
  });

  test('should work for different scopes within original grant', async ({ page }) => {
    const client = TEST_CLIENTS.public;
    const user = TEST_USERS.standard;

    // Login with broad scope
    const pkce1 = generatePKCE();
    await page.goto(buildAuthorizationUrl({
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      scope: 'openid profile email',
      state: generateState(),
      codeChallenge: pkce1.challenge,
      codeChallengeMethod: 'S256',
    }));

    await login(page, user.email, user.password);
    await page.waitForURL(url => url.href.startsWith(client.redirect_uris[0]));

    // Silent auth with narrower scope
    const pkce2 = generatePKCE();
    await page.goto(buildAuthorizationUrl({
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      scope: 'openid', // Narrower scope
      state: generateState(),
      codeChallenge: pkce2.challenge,
      codeChallengeMethod: 'S256',
      prompt: 'none',
    }));

    await page.waitForURL(url => url.href.startsWith(client.redirect_uris[0]));

    // Should succeed with active session
    const code = extractCodeFromUrl(page.url());
    expect(code).toBeTruthy();
  });

  test('should return login_required when no session exists', async ({ page, context }) => {
    const client = TEST_CLIENTS.public;

    // Clear all cookies to ensure no session
    await context.clearCookies();

    // Try silent auth without any prior login
    const pkce = generatePKCE();
    const state = generateState();

    await page.goto(buildAuthorizationUrl({
      clientId: client.client_id,
      redirectUri: client.redirect_uris[0],
      scope: 'openid',
      state,
      codeChallenge: pkce.challenge,
      codeChallengeMethod: 'S256',
      prompt: 'none',
    }));

    await page.waitForURL(url => url.href.startsWith(client.redirect_uris[0]));

    // Should return login_required error
    const error = extractErrorFromUrl(page.url());
    expect(error).toBeTruthy();
    expect(error!.error).toBe('login_required');
  });
});
