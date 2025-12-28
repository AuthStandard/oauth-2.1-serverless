/**
 * OAuth 2.1 Token Endpoint - Grant Type Handlers
 *
 * Exports all supported grant type handlers per OAuth 2.1:
 *
 * - authorization_code (Section 4.1.3):
 *   Exchange authorization code for tokens. Requires PKCE.
 *   Used by web apps, SPAs, and native apps.
 *
 * - refresh_token (Section 4.3):
 *   Obtain new tokens using a refresh token. Mandatory rotation.
 *   Used to maintain long-lived sessions without re-authentication.
 *
 * - client_credentials (Section 4.2):
 *   Machine-to-machine authentication. Confidential clients only.
 *   Used for backend service-to-service communication.
 *
 * Note: OAuth 2.1 removes the implicit and resource owner password grants
 * that were available in OAuth 2.0.
 *
 * @module oauth2_token/grants
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-14
 */

export { handleAuthorizationCodeGrant } from './authorization-code';
export { handleRefreshTokenGrant } from './refresh-token';
export { handleClientCredentialsGrant } from './client-credentials';
