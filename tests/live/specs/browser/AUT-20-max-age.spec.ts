/**
 * AUT-20: Max Age (Session Check)
 *
 * Validates that the max_age parameter is accepted and processed.
 * When max_age is specified, the authorization server should require
 * re-authentication if the user's session is older than max_age seconds.
 */

import { test, expect } from '@playwright/test';
import {
    generatePKCE,
    generateState,
    buildAuthorizationUrl,
    login,
    extractCodeFromUrl,
    TEST_CLIENTS,
    TEST_USERS,
} from '../../support/browser';

test.describe('AUT-20: Max Age Parameter', () => {
    test('should force re-authentication when session exceeds max_age', async ({ page }) => {
        const client = TEST_CLIENTS.public;
        const user = TEST_USERS.standard;

        // 1. First, establish an initial session
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

        // Wait for redirect with code to confirm logged in
        await page.waitForURL(url => url.href.startsWith(client.redirect_uris[0]));
        expect(extractCodeFromUrl(page.url())).toBeTruthy();

        // 2. Now try to authorize again WITH max_age=0
        // max_age=0 should force re-authentication regardless of the session age
        const pkce2 = generatePKCE();
        const state2 = generateState();

        const authUrlWithMaxAge = buildAuthorizationUrl({
            clientId: client.client_id,
            redirectUri: client.redirect_uris[0],
            scope: 'openid profile',
            state: state2,
            codeChallenge: pkce2.challenge,
            codeChallengeMethod: 'S256',
            maxAge: 0, // Force re-auth
        });

        await page.goto(authUrlWithMaxAge);

        // 3. Verify we are back at the login page even though we just logged in
        // This assumes the login page has an email input field
        const emailInput = page.locator('input[name="email"]');
        await expect(emailInput).toBeVisible({ timeout: 10000 });

        // 4. Login again and verify we get a new code
        await login(page, user.email, user.password);
        await page.waitForURL(url => url.href.startsWith(client.redirect_uris[0]));

        const secondCode = extractCodeFromUrl(page.url());
        expect(secondCode).toBeTruthy();
    });

    test('should NOT force re-authentication when session is within max_age', async ({ page }) => {
        const client = TEST_CLIENTS.public;
        const user = TEST_USERS.standard;

        // 1. Establish session
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

        // 2. Authorize again with prompt=none and large max_age (e.g., 3600 seconds)
        // Per OIDC Core 1.0, silent auth (prompt=none) with max_age should return
        // a code directly if session age is within max_age.
        const pkce2 = generatePKCE();
        const state2 = generateState();

        await page.goto(buildAuthorizationUrl({
            clientId: client.client_id,
            redirectUri: client.redirect_uris[0],
            scope: 'openid',
            state: state2,
            codeChallenge: pkce2.challenge,
            codeChallengeMethod: 'S256',
            maxAge: 3600,
            prompt: 'none', // Silent auth requires prompt=none
        }));

        // 3. Should redirect directly to callback (no login UI)
        await page.waitForURL(url => url.href.startsWith(client.redirect_uris[0]), {
            timeout: 10000,
        });

        const code = extractCodeFromUrl(page.url());
        expect(code).toBeTruthy();
    });
});
