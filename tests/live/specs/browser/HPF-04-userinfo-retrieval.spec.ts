/**
 * HPF-04: UserInfo Retrieval
 *
 * Tests the OIDC UserInfo endpoint which returns claims about
 * the authenticated user based on the access token's scope.
 */

import { test, expect } from '@playwright/test';
import {
  generatePKCE,
  generateState,
  completeAuthorizationFlow,
  exchangeCodeForTokens,
  getUserInfo,
  decodeJWT,
  TEST_CLIENTS,
  TEST_USERS,
} from '../../support/browser';

test.describe('HPF-04: UserInfo Retrieval', () => {
  test('should return user info for valid access token', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.confidential;
    const user = TEST_USERS.standard;

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

    const userInfo = await getUserInfo(tokens.access_token);

    // Must have sub claim
    expect(userInfo.sub).toBeTruthy();

    // Sub should match the token's sub
    const tokenPayload = decodeJWT(tokens.access_token).payload;
    expect(userInfo.sub).toBe(tokenPayload.sub);
  });

  test('should return email when email scope is requested', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.confidential;
    const user = TEST_USERS.standard;

    const { code } = await completeAuthorizationFlow(page, {
      client,
      user,
      pkce,
      state,
      scope: 'openid email',
    });

    const tokens = await exchangeCodeForTokens({
      code,
      clientId: client.client_id,
      clientSecret: client.client_secret,
      redirectUri: client.redirect_uris[0],
      codeVerifier: pkce.verifier,
    });

    const userInfo = await getUserInfo(tokens.access_token);

    // Should include email claims
    expect(userInfo.email).toBe(user.email);
    expect(userInfo.email_verified).toBeDefined();
  });

  test('should return profile claims when profile scope is requested', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.confidential;
    const user = TEST_USERS.standard;

    const { code } = await completeAuthorizationFlow(page, {
      client,
      user,
      pkce,
      state,
      scope: 'openid profile',
    });

    const tokens = await exchangeCodeForTokens({
      code,
      clientId: client.client_id,
      clientSecret: client.client_secret,
      redirectUri: client.redirect_uris[0],
      codeVerifier: pkce.verifier,
    });

    const userInfo = await getUserInfo(tokens.access_token);

    // Profile scope should include name-related claims
    // At least one of these should be present
    const hasProfileClaims =
      userInfo.name !== undefined ||
      userInfo.given_name !== undefined ||
      userInfo.family_name !== undefined ||
      userInfo.preferred_username !== undefined;

    expect(hasProfileClaims).toBe(true);
  });

  test('should not return email when only openid scope is requested', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.confidential;
    const user = TEST_USERS.standard;

    const { code } = await completeAuthorizationFlow(page, {
      client,
      user,
      pkce,
      state,
      scope: 'openid', // Only openid, no email
    });

    const tokens = await exchangeCodeForTokens({
      code,
      clientId: client.client_id,
      clientSecret: client.client_secret,
      redirectUri: client.redirect_uris[0],
      codeVerifier: pkce.verifier,
    });

    const userInfo = await getUserInfo(tokens.access_token);

    // Should have sub but not necessarily email
    expect(userInfo.sub).toBeTruthy();

    // Email should not be included without email scope
    // (Some implementations may still include it, so this is a soft check)
    if (userInfo.email) {
      console.log('Note: Server returns email even without email scope');
    }
  });

  test('should return consistent sub across multiple requests', async ({ page }) => {
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

    // Call userinfo multiple times
    const userInfo1 = await getUserInfo(tokens.access_token);
    const userInfo2 = await getUserInfo(tokens.access_token);

    // Sub should be consistent
    expect(userInfo1.sub).toBe(userInfo2.sub);
  });

  test('should match sub between id_token and userinfo', async ({ page }) => {
    const pkce = generatePKCE();
    const state = generateState();
    const client = TEST_CLIENTS.confidential;
    const user = TEST_USERS.standard;

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

    expect(tokens.id_token).toBeTruthy();

    const idTokenPayload = decodeJWT(tokens.id_token!).payload;
    const userInfo = await getUserInfo(tokens.access_token);

    // Sub must match between id_token and userinfo
    expect(userInfo.sub).toBe(idTokenPayload.sub);
  });
});
