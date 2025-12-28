/**
 * USR-05: Get Me (SCIM Self-Service)
 *
 * Tests the /scim/Me endpoint which allows users to retrieve
 * their own profile using their access token.
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
  schemas?: string[];
  id?: string;
  userName?: string;
  emails?: Array<{ value: string; primary?: boolean }>;
}

test.describe('USR-05: Get Me (SCIM Self-Service)', () => {
  test('should return user profile for valid access token', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.confidential;
    const user = TEST_USERS.standard;

    // Get user access token via auth code flow
    const { code } = await completeAuthorizationFlow(page, {
      client,
      user,
      pkce,
      state,
      scope: 'openid profile email',
    });

    const tokens = await exchangeCodeForTokens({
      code,
      clientId: client.client_id,
      clientSecret: client.client_secret,
      redirectUri: client.redirect_uris[0],
      codeVerifier: pkce.verifier,
    });

    // Call /scim/Me with user's access token
    const response = await fetch(`${config.apiBaseUrl}${ENDPOINTS.scimMe}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${tokens.access_token}`,
      },
    });

    expect(response.status).toBe(200);

    const profile = await response.json() as ScimUser;

    // Verify SCIM response structure
    expect(profile.schemas).toContain('urn:ietf:params:scim:schemas:core:2.0:User');
    expect(profile.id).toBeTruthy();
    expect(profile.userName).toBe(user.email);

    // Should include email if scope was requested
    if (profile.emails && profile.emails.length > 0) {
      expect(profile.emails[0].value).toBe(user.email);
    }
  });

  test('should reject request without access token', async () => {
    const response = await fetch(`${config.apiBaseUrl}${ENDPOINTS.scimMe}`, {
      method: 'GET',
      // No Authorization header
    });

    expect(response.status).toBe(401);
  });

  test('should reject request with invalid access token', async () => {
    const response = await fetch(`${config.apiBaseUrl}${ENDPOINTS.scimMe}`, {
      method: 'GET',
      headers: {
        'Authorization': 'Bearer invalid-token-12345',
      },
    });

    expect(response.status).toBe(401);
  });

  test('should return consistent user ID', async ({ page }) => {
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

    // Call /scim/Me twice
    const response1 = await fetch(`${config.apiBaseUrl}${ENDPOINTS.scimMe}`, {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${tokens.access_token}` },
    });

    const response2 = await fetch(`${config.apiBaseUrl}${ENDPOINTS.scimMe}`, {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${tokens.access_token}` },
    });

    const profile1 = await response1.json() as ScimUser;
    const profile2 = await response2.json() as ScimUser;

    // User ID should be consistent
    expect(profile1.id).toBe(profile2.id);
    expect(profile1.userName).toBe(profile2.userName);
  });
});
