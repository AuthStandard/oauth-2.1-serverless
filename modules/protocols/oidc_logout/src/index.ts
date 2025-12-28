/**
 * OIDC RP-Initiated Logout Endpoint - Lambda Handler
 *
 * Implements GET /connect/logout per OpenID Connect RP-Initiated Logout 1.0.
 * Enables Relying Parties to request user logout from the Authorization Server.
 *
 * Request: GET /connect/logout
 *   - id_token_hint (REQUIRED): ID Token previously issued to the RP
 *   - post_logout_redirect_uri (OPTIONAL): URL to redirect after logout
 *   - state (OPTIONAL): Opaque value for maintaining state
 *   - client_id (OPTIONAL): Client identifier (used if id_token_hint missing)
 *
 * Response:
 *   - If valid post_logout_redirect_uri: HTTP 303 redirect with state
 *   - Otherwise: HTML page confirming logout
 *   - Session cookie cleared via Set-Cookie header
 *
 * Security Controls:
 *   - ID token signature verification using KMS public key
 *   - Issuer validation (iss claim must match expected issuer)
 *   - post_logout_redirect_uri must be registered with client
 *   - Session deletion from DynamoDB
 *   - HttpOnly session cookie cleared
 *   - SOC2-compliant structured audit logging
 *
 * Environment Variables (injected via Terraform):
 *   - TABLE_NAME: DynamoDB table name
 *   - KMS_KEY_ID: AWS KMS key ID for JWT verification
 *   - ISSUER: OAuth 2.1 issuer URL
 *   - SESSION_COOKIE_NAME: Name of the session cookie
 *   - SESSION_COOKIE_DOMAIN: Domain for the session cookie (optional)
 *   - DEFAULT_LOGOUT_REDIRECT_URL: Fallback redirect URL
 *
 * @module oidc_logout
 * @see https://openid.net/specs/openid-connect-rpinitiated-1_0.html
 */

import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2, Context } from 'aws-lambda';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { createLogger, withContext } from '@oauth-server/shared';

import type { EnvConfig } from './types';
import { parseLogoutParams, validateRequiredParams, verifyIdToken, validatePostLogoutRedirectUri, extractClientIdFromToken } from './validation';
import { logoutRedirect, logoutConfirmationPage, logoutError, serverError, buildClearCookieHeader } from './responses';
import { deleteSession, deleteUserSessions } from './session';
import { getClient } from './client';
import { getPublicKey } from './kms';

// =============================================================================
// Environment Configuration
// =============================================================================

/** Cached configuration to avoid repeated env lookups */
let envConfig: EnvConfig | null = null;

/**
 * Load and validate environment configuration.
 * All values are injected by Terraform - no hardcoded defaults.
 *
 * @throws Error if required environment variables are missing
 */
function getEnvConfig(): EnvConfig {
    if (envConfig) return envConfig;

    const tableName = process.env.TABLE_NAME;
    const kmsKeyId = process.env.KMS_KEY_ID;
    const issuer = process.env.ISSUER;
    const sessionCookieName = process.env.SESSION_COOKIE_NAME;
    const sessionCookieDomain = process.env.SESSION_COOKIE_DOMAIN || '';
    const defaultLogoutRedirectUrl = process.env.DEFAULT_LOGOUT_REDIRECT_URL || '';

    if (!tableName) throw new Error('TABLE_NAME environment variable is required');
    if (!kmsKeyId) throw new Error('KMS_KEY_ID environment variable is required');
    if (!issuer) throw new Error('ISSUER environment variable is required');
    if (!sessionCookieName) throw new Error('SESSION_COOKIE_NAME environment variable is required');

    envConfig = {
        tableName,
        kmsKeyId,
        issuer,
        sessionCookieName,
        sessionCookieDomain,
        defaultLogoutRedirectUrl,
    };

    return envConfig;
}

// =============================================================================
// DynamoDB Client Singleton
// =============================================================================

/** Cached DynamoDB client for Lambda warm starts */
let docClient: DynamoDBDocumentClient | null = null;

/**
 * Get or create DynamoDB document client.
 * Uses singleton pattern to reuse connections across Lambda invocations.
 */
function getDocClient(): DynamoDBDocumentClient {
    if (!docClient) {
        const client = new DynamoDBClient({});
        docClient = DynamoDBDocumentClient.from(client, {
            marshallOptions: { removeUndefinedValues: true },
        });
    }
    return docClient;
}

// =============================================================================
// Lambda Handler
// =============================================================================

export const handler = async (
    event: APIGatewayProxyEventV2,
    context: Context
): Promise<APIGatewayProxyResultV2> => {
    const logger = createLogger(event, context);
    const auditLogger = withContext(event, context);

    try {
        const method = event.requestContext.http.method;
        logger.info('Logout request received', { method });

        // Only GET is allowed per OIDC RP-Initiated Logout 1.0
        if (method !== 'GET') {
            logger.warn('Invalid HTTP method', { method });
            return logoutError('invalid_request', 'Method not allowed. Use GET.');
        }

        // Load configuration
        const config = getEnvConfig();

        // Parse query parameters
        const params = parseLogoutParams(event.queryStringParameters || {});

        // Validate required parameters
        const validationError = validateRequiredParams(params);
        if (validationError) {
            logger.warn('Missing required parameter', { error: validationError });
            return logoutError('invalid_request', validationError);
        }

        // Verify ID token signature and extract claims
        const publicKey = await getPublicKey(config.kmsKeyId);
        const tokenPayload = verifyIdToken(params.id_token_hint!, publicKey, config.issuer);

        if (!tokenPayload) {
            logger.warn('ID token verification failed');
            return logoutError('invalid_request', 'Invalid or malformed id_token_hint');
        }

        const sub = tokenPayload.sub;
        const clientId = extractClientIdFromToken(tokenPayload);
        const sessionId = tokenPayload.sid;

        logger.info('ID token verified', { sub, clientId, hasSessionId: !!sessionId });

        // Get DynamoDB client
        const client = getDocClient();

        // Delete session(s) from DynamoDB
        let sessionsDeleted = 0;
        if (sessionId) {
            // Delete specific session if sid claim is present
            await deleteSession(client, config.tableName, sessionId);
            sessionsDeleted = 1;
            logger.info('Deleted specific session', { sessionId });
        } else {
            // Delete all sessions for the user
            sessionsDeleted = await deleteUserSessions(client, config.tableName, sub);
            logger.info('Deleted user sessions', { sub, count: sessionsDeleted });
        }

        // Build Set-Cookie header to clear session cookie
        const clearCookieHeader = buildClearCookieHeader(
            config.sessionCookieName,
            config.sessionCookieDomain || undefined
        );

        // Audit log the logout event
        auditLogger.log({
            action: 'LOGOUT',
            actor: { type: 'USER', sub },
            details: {
                clientId,
                sessionId: sessionId || 'all',
                sessionsDeleted,
            },
        });

        // Determine redirect behavior
        if (params.post_logout_redirect_uri) {
            // Validate post_logout_redirect_uri against client configuration
            const clientRecord = await getClient(client, config.tableName, clientId);

            if (!clientRecord) {
                logger.warn('Client not found', { clientId });
                // Still logout, but show confirmation page instead of redirecting
                return logoutConfirmationPage(config.issuer, clearCookieHeader);
            }

            if (validatePostLogoutRedirectUri(params.post_logout_redirect_uri, clientRecord)) {
                logger.info('Redirecting to post_logout_redirect_uri', {
                    redirectUri: params.post_logout_redirect_uri,
                });
                return logoutRedirect(
                    params.post_logout_redirect_uri,
                    params.state,
                    clearCookieHeader
                );
            } else {
                logger.warn('Invalid post_logout_redirect_uri', {
                    requestedUri: params.post_logout_redirect_uri,
                    clientId,
                });
                // Invalid redirect URI - show confirmation page instead
                return logoutConfirmationPage(config.issuer, clearCookieHeader);
            }
        }

        // No redirect URI provided - show confirmation page
        logger.info('Showing logout confirmation page');
        return logoutConfirmationPage(config.issuer, clearCookieHeader);

    } catch (err) {
        const error = err as Error;
        logger.error('Logout endpoint error', { error: error.message, stack: error.stack });
        return serverError('An unexpected error occurred');
    }
};
