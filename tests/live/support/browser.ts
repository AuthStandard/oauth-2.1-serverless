/**
 * Browser Test Helpers
 *
 * Shared utilities for Playwright browser tests.
 */

import { Page } from '@playwright/test';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { config, ENDPOINTS } from '../setup';

// Re-export config and endpoints
export { config, ENDPOINTS };

// =============================================================================
// Fixtures
// =============================================================================

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtures = JSON.parse(readFileSync(join(__dirname, '../fixtures.json'), 'utf-8'));

export const TEST_CLIENTS = {
  confidential: {
    client_id: fixtures.clients['test-app'].client_id,
    client_secret: fixtures.clients['test-app'].client_secret,
    redirect_uris: [fixtures.clients['test-app'].redirect_uri],
  },
  public: {
    client_id: fixtures.clients['test-public-app'].client_id,
    redirect_uris: [fixtures.clients['test-public-app'].redirect_uri],
  },
  adminCli: {
    client_id: fixtures.clients['admin-cli'].client_id,
    client_secret: fixtures.clients['admin-cli'].client_secret,
  },
};

export const TEST_USERS = {
  standard: fixtures.users['test-user-001'],
  admin: fixtures.users['test-user-002'],
};

// =============================================================================
// PKCE & State Generation
// =============================================================================

/**
 * Generate PKCE challenge and verifier pair.
 */
export function generatePKCE(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

/**
 * Generate random state parameter.
 */
export function generateState(): string {
  return randomBytes(16).toString('base64url');
}

/**
 * Generate random nonce for OIDC.
 */
export function generateNonce(): string {
  return randomBytes(16).toString('base64url');
}

// =============================================================================
// URL Building
// =============================================================================

export interface AuthorizationUrlParams {
  clientId: string;
  redirectUri: string;
  scope?: string;
  state?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  prompt?: string;
  nonce?: string;
  maxAge?: number;
}

/**
 * Build authorization URL with all required parameters.
 */
export function buildAuthorizationUrl(params: AuthorizationUrlParams): string {
  const url = new URL(ENDPOINTS.authorize, config.apiBaseUrl);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', params.clientId);
  url.searchParams.set('redirect_uri', params.redirectUri);
  url.searchParams.set('scope', params.scope || 'openid');

  if (params.state) url.searchParams.set('state', params.state);
  if (params.codeChallenge) url.searchParams.set('code_challenge', params.codeChallenge);
  if (params.codeChallengeMethod) url.searchParams.set('code_challenge_method', params.codeChallengeMethod);
  if (params.prompt) url.searchParams.set('prompt', params.prompt);
  if (params.nonce) url.searchParams.set('nonce', params.nonce);
  if (params.maxAge !== undefined) url.searchParams.set('max_age', params.maxAge.toString());

  return url.toString();
}

/**
 * Build logout URL.
 */
export function buildLogoutUrl(params: {
  idTokenHint?: string;
  postLogoutRedirectUri?: string;
  state?: string;
}): string {
  const url = new URL(ENDPOINTS.logout, config.apiBaseUrl);
  if (params.idTokenHint) url.searchParams.set('id_token_hint', params.idTokenHint);
  if (params.postLogoutRedirectUri) url.searchParams.set('post_logout_redirect_uri', params.postLogoutRedirectUri);
  if (params.state) url.searchParams.set('state', params.state);
  return url.toString();
}

// =============================================================================
// Login Helpers
// =============================================================================

/**
 * Login via the password form.
 * Fills in email/password and submits the form.
 */
export async function login(page: Page, email: string, password: string): Promise<void> {
  // Wait for login form to be visible
  await page.waitForSelector('input[name="email"], input[type="email"]', { timeout: 10000 });

  // Fill credentials
  await page.fill('input[name="email"], input[type="email"]', email);
  await page.fill('input[name="password"], input[type="password"]', password);

  // Submit form
  await page.click('button[type="submit"], input[type="submit"]');
}

/**
 * Complete the full authorization flow and return the authorization code.
 */
export async function completeAuthorizationFlow(
  page: Page,
  params: {
    client: { client_id: string; redirect_uris: string[] };
    user: { email: string; password: string };
    scope?: string;
    pkce: { verifier: string; challenge: string };
    state: string;
  }
): Promise<{ code: string; state: string }> {
  const authUrl = buildAuthorizationUrl({
    clientId: params.client.client_id,
    redirectUri: params.client.redirect_uris[0],
    scope: params.scope || 'openid profile email',
    state: params.state,
    codeChallenge: params.pkce.challenge,
    codeChallengeMethod: 'S256',
  });

  await page.goto(authUrl);
  await login(page, params.user.email, params.user.password);

  // Wait for redirect back to client
  await page.waitForURL(url => url.href.startsWith(params.client.redirect_uris[0]), {
    timeout: 30000,
  });

  const redirectUrl = page.url();
  const code = extractCodeFromUrl(redirectUrl);
  const returnedState = extractStateFromUrl(redirectUrl);

  if (!code) {
    throw new Error(`No authorization code in redirect URL: ${redirectUrl}`);
  }

  return { code, state: returnedState || '' };
}

// =============================================================================
// URL Extraction
// =============================================================================

/**
 * Extract authorization code from redirect URL.
 */
export function extractCodeFromUrl(url: string): string | null {
  const parsed = new URL(url);
  return parsed.searchParams.get('code');
}

/**
 * Extract state from redirect URL.
 */
export function extractStateFromUrl(url: string): string | null {
  const parsed = new URL(url);
  return parsed.searchParams.get('state');
}

/**
 * Extract error from redirect URL.
 */
export function extractErrorFromUrl(url: string): { error: string; description?: string } | null {
  const parsed = new URL(url);
  const error = parsed.searchParams.get('error');
  if (!error) return null;
  return {
    error,
    description: parsed.searchParams.get('error_description') || undefined,
  };
}

// =============================================================================
// Token Operations
// =============================================================================

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  id_token?: string;
  refresh_token?: string;
  scope?: string;
}

export interface TokenErrorResponse {
  error: string;
  error_description?: string;
}

/**
 * Exchange authorization code for tokens.
 */
export async function exchangeCodeForTokens(params: {
  code: string;
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
  codeVerifier?: string;
}): Promise<TokenResponse> {
  const body = new URLSearchParams();
  body.set('grant_type', 'authorization_code');
  body.set('code', params.code);
  body.set('redirect_uri', params.redirectUri);
  body.set('client_id', params.clientId);
  if (params.codeVerifier) body.set('code_verifier', params.codeVerifier);

  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
  };

  if (params.clientSecret) {
    const credentials = Buffer.from(`${params.clientId}:${params.clientSecret}`).toString('base64');
    headers['Authorization'] = `Basic ${credentials}`;
  }

  const response = await fetch(`${config.apiBaseUrl}${ENDPOINTS.token}`, {
    method: 'POST',
    headers,
    body: body.toString(),
  });

  if (!response.ok) {
    const errorBody = await response.json() as TokenErrorResponse;
    throw new Error(`Token exchange failed: ${errorBody.error} - ${errorBody.error_description}`);
  }

  return response.json() as Promise<TokenResponse>;
}

/**
 * Exchange authorization code for tokens, expecting an error.
 */
export async function exchangeCodeForTokensExpectError(params: {
  code: string;
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
  codeVerifier?: string;
}): Promise<{ status: number; error: TokenErrorResponse }> {
  const body = new URLSearchParams();
  body.set('grant_type', 'authorization_code');
  body.set('code', params.code);
  body.set('redirect_uri', params.redirectUri);
  body.set('client_id', params.clientId);
  if (params.codeVerifier) body.set('code_verifier', params.codeVerifier);

  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
  };

  if (params.clientSecret) {
    const credentials = Buffer.from(`${params.clientId}:${params.clientSecret}`).toString('base64');
    headers['Authorization'] = `Basic ${credentials}`;
  }

  const response = await fetch(`${config.apiBaseUrl}${ENDPOINTS.token}`, {
    method: 'POST',
    headers,
    body: body.toString(),
  });

  const errorBody = await response.json() as TokenErrorResponse;
  return { status: response.status, error: errorBody };
}

/**
 * Refresh an access token using a refresh token.
 */
export async function refreshAccessToken(params: {
  refreshToken: string;
  clientId: string;
  clientSecret?: string;
  scope?: string;
}): Promise<TokenResponse> {
  const body = new URLSearchParams();
  body.set('grant_type', 'refresh_token');
  body.set('refresh_token', params.refreshToken);
  body.set('client_id', params.clientId);
  if (params.scope) body.set('scope', params.scope);

  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
  };

  if (params.clientSecret) {
    const credentials = Buffer.from(`${params.clientId}:${params.clientSecret}`).toString('base64');
    headers['Authorization'] = `Basic ${credentials}`;
  }

  const response = await fetch(`${config.apiBaseUrl}${ENDPOINTS.token}`, {
    method: 'POST',
    headers,
    body: body.toString(),
  });

  if (!response.ok) {
    const errorBody = await response.json() as TokenErrorResponse;
    throw new Error(`Token refresh failed: ${errorBody.error} - ${errorBody.error_description}`);
  }

  return response.json() as Promise<TokenResponse>;
}

/**
 * Refresh token expecting an error.
 */
export async function refreshAccessTokenExpectError(params: {
  refreshToken: string;
  clientId: string;
  clientSecret?: string;
  scope?: string;
}): Promise<{ status: number; error: TokenErrorResponse }> {
  const body = new URLSearchParams();
  body.set('grant_type', 'refresh_token');
  body.set('refresh_token', params.refreshToken);
  body.set('client_id', params.clientId);
  if (params.scope) body.set('scope', params.scope);

  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
  };

  if (params.clientSecret) {
    const credentials = Buffer.from(`${params.clientId}:${params.clientSecret}`).toString('base64');
    headers['Authorization'] = `Basic ${credentials}`;
  }

  const response = await fetch(`${config.apiBaseUrl}${ENDPOINTS.token}`, {
    method: 'POST',
    headers,
    body: body.toString(),
  });

  const errorBody = await response.json() as TokenErrorResponse;
  return { status: response.status, error: errorBody };
}

// =============================================================================
// Token Revocation
// =============================================================================

/**
 * Revoke a token.
 */
export async function revokeToken(params: {
  token: string;
  tokenTypeHint?: 'access_token' | 'refresh_token';
  clientId: string;
  clientSecret?: string;
}): Promise<{ status: number }> {
  const body = new URLSearchParams();
  body.set('token', params.token);
  if (params.tokenTypeHint) body.set('token_type_hint', params.tokenTypeHint);

  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
  };

  if (params.clientSecret) {
    const credentials = Buffer.from(`${params.clientId}:${params.clientSecret}`).toString('base64');
    headers['Authorization'] = `Basic ${credentials}`;
  }

  const response = await fetch(`${config.apiBaseUrl}${ENDPOINTS.revoke}`, {
    method: 'POST',
    headers,
    body: body.toString(),
  });

  return { status: response.status };
}

// =============================================================================
// Token Introspection
// =============================================================================

export interface IntrospectionResponse {
  active: boolean;
  scope?: string;
  client_id?: string;
  username?: string;
  token_type?: string;
  exp?: number;
  iat?: number;
  sub?: string;
  aud?: string;
  iss?: string;
}

/**
 * Introspect a token.
 */
export async function introspectToken(params: {
  token: string;
  tokenTypeHint?: 'access_token' | 'refresh_token';
  clientId: string;
  clientSecret: string;
}): Promise<IntrospectionResponse> {
  const body = new URLSearchParams();
  body.set('token', params.token);
  if (params.tokenTypeHint) body.set('token_type_hint', params.tokenTypeHint);

  const credentials = Buffer.from(`${params.clientId}:${params.clientSecret}`).toString('base64');

  const response = await fetch(`${config.apiBaseUrl}${ENDPOINTS.introspect}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${credentials}`,
    },
    body: body.toString(),
  });

  return response.json() as Promise<IntrospectionResponse>;
}

// =============================================================================
// UserInfo
// =============================================================================

export interface UserInfoResponse {
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  [key: string]: unknown;
}

/**
 * Get user info using an access token.
 */
export async function getUserInfo(accessToken: string): Promise<UserInfoResponse> {
  const response = await fetch(`${config.apiBaseUrl}${ENDPOINTS.userinfo}`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    throw new Error(`UserInfo request failed: ${response.status}`);
  }

  return response.json() as Promise<UserInfoResponse>;
}

// =============================================================================
// JWT Utilities
// =============================================================================

/**
 * Decode a JWT without verification (for inspection only).
 */
export function decodeJWT(token: string): { header: Record<string, unknown>; payload: Record<string, unknown> } {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format');
  }

  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf-8'));
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf-8'));

  return { header, payload };
}

// =============================================================================
// Wait Helpers
// =============================================================================

/**
 * Wait for redirect to a specific URL pattern.
 */
export async function waitForRedirect(page: Page, urlPattern: string | RegExp): Promise<string> {
  await page.waitForURL(urlPattern, { timeout: 30000 });
  return page.url();
}

/**
 * Wait for a specific amount of time.
 */
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
