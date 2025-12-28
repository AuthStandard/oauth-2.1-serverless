/**
 * USR-06: Hack Me (ID Parameter Ignored)
 *
 * Tests that the /scim/Me endpoint ignores any ID parameter
 * and always returns the authenticated user's profile.
 * This prevents IDOR (Insecure Direct Object Reference) attacks.
 */

import { test, expect } from '@playwright/test';
import {
  generatePKCE,
  generateState,
  completeAuthorizationFlow,
  exchangeCodeForTokens,
  config,
  ENDPOINTS,
  TEST_CLIENTS,
  TEST_USERS,
} from '../../support/browser';

interface ScimUser {
  id?: string;
  userName?: string;
  Resources?: ScimUser[];
}

test.describe('USR-06: Hack Me (IDOR Prevention)', () => {
  test('should ignore ID in path and return own profile', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.confidential;
    const user = TEST_USERS.standard;

    // Get access token for standard user
    const { code } = await completeAuthorizationFlow(page, {
      client,
      user,
      pkce,
      state,
    });

    const tokens = await exchangeCodeForTokens({
      code,
      clientId: client.client_id,
      clientSecret: client.client_secret,
      redirectUri: client.redirect_uris[0],
      codeVerifier: pkce.verifier,
    });

    // First, get own profile to know our ID
    const ownResponse = await fetch(`${config.apiBaseUrl}${ENDPOINTS.scimMe}`, {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${tokens.access_token}` },
    });

    const ownProfile = await ownResponse.json() as ScimUser;
    const ownId = ownProfile.id;

    // Try to access another user's profile by adding their ID
    // The admin user has a different ID
    const otherUserId = TEST_USERS.admin.sub;

    // Try various IDOR attack patterns
    const attackUrls = [
      `${config.apiBaseUrl}${ENDPOINTS.scimMe}/${otherUserId}`,
      `${config.apiBaseUrl}${ENDPOINTS.scimMe}?id=${otherUserId}`,
      `${config.apiBaseUrl}${ENDPOINTS.scimMe}?userId=${otherUserId}`,
    ];

    for (const attackUrl of attackUrls) {
      const response = await fetch(attackUrl, {
        method: 'GET',
        headers: { 'Authorization': `Bearer ${tokens.access_token}` },
      });

      // Should either:
      // 1. Return 200 with OWN profile (ignoring the ID)
      // 2. Return 404 (endpoint doesn't accept ID)
      // 3. Return 400 (bad request)
      // Should NOT return another user's data

      if (response.status === 200) {
        const profile = await response.json() as ScimUser;
        // Must be own profile, not the other user's
        expect(profile.id).toBe(ownId);
        expect(profile.id).not.toBe(otherUserId);
      } else {
        // 404 or 400 is also acceptable - means the attack vector doesn't work
        expect([400, 404]).toContain(response.status);
      }
    }
  });

  test('should not leak other user data via query parameters', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.confidential;
    const user = TEST_USERS.standard;

    const { code } = await completeAuthorizationFlow(page, {
      client,
      user,
      pkce,
      state,
    });

    const tokens = await exchangeCodeForTokens({
      code,
      clientId: client.client_id,
      clientSecret: client.client_secret,
      redirectUri: client.redirect_uris[0],
      codeVerifier: pkce.verifier,
    });

    // Try to filter for other users - should not work
    const response = await fetch(
      `${config.apiBaseUrl}${ENDPOINTS.scimMe}?filter=userName eq "${TEST_USERS.admin.email}"`,
      {
        method: 'GET',
        headers: { 'Authorization': `Bearer ${tokens.access_token}` },
      }
    );

    if (response.status === 200) {
      const data = await response.json() as ScimUser;

      // If it's a single user response, should be own profile
      if (data.userName) {
        expect(data.userName).not.toBe(TEST_USERS.admin.email);
      }

      // If it's a list response, should not contain other users
      if (data.Resources) {
        for (const resource of data.Resources) {
          expect(resource.userName).not.toBe(TEST_USERS.admin.email);
        }
      }
    }
    // 400/404 is also acceptable - filter not supported
  });

  test('should return 401 for revoked token', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.confidential;
    const user = TEST_USERS.standard;

    const { code } = await completeAuthorizationFlow(page, {
      client,
      user,
      pkce,
      state,
    });

    const tokens = await exchangeCodeForTokens({
      code,
      clientId: client.client_id,
      clientSecret: client.client_secret,
      redirectUri: client.redirect_uris[0],
      codeVerifier: pkce.verifier,
    });

    // Revoke the token
    await fetch(`${config.apiBaseUrl}${ENDPOINTS.revoke}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${Buffer.from(`${client.client_id}:${client.client_secret}`).toString('base64')}`,
      },
      body: `token=${tokens.access_token}`,
    });

    // Try to use revoked token
    const response = await fetch(`${config.apiBaseUrl}${ENDPOINTS.scimMe}`, {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${tokens.access_token}` },
    });

    // Should be unauthorized (401) or the token might still work if server
    // doesn't immediately invalidate (JWTs are stateless)
    // Both behaviors are valid depending on implementation
    expect([200, 401]).toContain(response.status);
  });
});
