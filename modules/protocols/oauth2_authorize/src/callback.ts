/**
 * OAuth 2.1 Authorization Callback - Lambda Handler
 *
 * Implements GET /authorize/callback per OAuth 2.1 Section 4.1.2.
 * Completes the authorization flow after successful user authentication.
 *
 * Flow:
 *   1. Validate session_id parameter
 *   2. Fetch session from DynamoDB
 *   3. Validate redirect_uri exists (required for error redirects)
 *   4. Check session expiration (TTL)
 *   5. Verify user authentication (authenticatedUserId present)
 *   6. Validate required session fields (PKCE, clientId)
 *   7. Generate authorization code (256 bits entropy)
 *   8. Store code with PKCE binding (atomic with collision check)
 *   9. Delete consumed session (single-use)
 *  10. Audit log and respond with code (query string or form_post)
 *
 * Security:
 *   - Session TTL validation prevents replay attacks
 *   - Single-use sessions (deleted after code generation)
 *   - Issuer parameter in ALL responses (Section 7.14 mix-up mitigation)
 *   - 256-bit authorization codes exceed NIST SP 800-63B requirements
 *   - PKCE binding preserved for token endpoint verification
 *   - Atomic code storage with collision detection
 *   - response_mode=form_post support for enhanced security
 *
 * @module oauth2_authorize/callback
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-14#section-4.1.2
 * @see https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
 */

import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2, Context } from 'aws-lambda';
import { randomBytes, randomUUID } from 'node:crypto';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, PutCommand, DeleteCommand } from '@aws-sdk/lib-dynamodb';
import {
    createLogger,
    withContext,
    redirect,
    invalidRequest,
    serverError,
    formPostResponse,
    formPostError,
} from '@oauth-server/shared';
import type { CallbackEnvConfig, LoginSessionItem, AuthCodeItem, AuthenticatedSessionItem } from './types';

// =============================================================================
// Constants
// =============================================================================

/** 32 bytes = 256 bits of entropy for authorization codes */
const AUTH_CODE_BYTES = 32;

// =============================================================================
// DynamoDB Client
// =============================================================================

let docClient: DynamoDBDocumentClient | null = null;

function getDocClient(): DynamoDBDocumentClient {
    if (!docClient) {
        docClient = DynamoDBDocumentClient.from(new DynamoDBClient({}), {
            marshallOptions: { removeUndefinedValues: true },
        });
    }
    return docClient;
}

// =============================================================================
// Environment Configuration
// =============================================================================

function getEnvConfig(): CallbackEnvConfig {
    const tableName = process.env.TABLE_NAME;
    const codeTtlSecondsStr = process.env.CODE_TTL_SECONDS;
    const issuer = process.env.ISSUER;
    const sessionCookieName = process.env.SESSION_COOKIE_NAME || '__Host-sid';
    const sessionCookieDomain = process.env.SESSION_COOKIE_DOMAIN;
    const authSessionTtlSecondsStr = process.env.AUTH_SESSION_TTL_SECONDS || '86400';

    if (!tableName) throw new Error('TABLE_NAME environment variable is required');
    if (!codeTtlSecondsStr) throw new Error('CODE_TTL_SECONDS environment variable is required');
    if (!issuer) throw new Error('ISSUER environment variable is required');

    const codeTtlSeconds = parseInt(codeTtlSecondsStr, 10);
    if (isNaN(codeTtlSeconds) || codeTtlSeconds <= 0) {
        throw new Error('CODE_TTL_SECONDS must be a positive integer');
    }

    const authSessionTtlSeconds = parseInt(authSessionTtlSecondsStr, 10);
    if (isNaN(authSessionTtlSeconds) || authSessionTtlSeconds <= 0) {
        throw new Error('AUTH_SESSION_TTL_SECONDS must be a positive integer');
    }

    return {
        tableName,
        codeTtlSeconds,
        issuer,
        sessionCookieName,
        sessionCookieDomain,
        authSessionTtlSeconds,
    };
}

// =============================================================================
// Authorization Code Generation
// =============================================================================

function generateAuthorizationCode(): string {
    return randomBytes(AUTH_CODE_BYTES)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

// =============================================================================
// Session Cookie Helpers
// =============================================================================

/**
 * Build a Set-Cookie header for the authenticated session.
 *
 * Uses secure cookie attributes per OWASP recommendations:
 * - HttpOnly: Prevents JavaScript access (XSS protection)
 * - Secure: Only sent over HTTPS
 * - SameSite=Lax: CSRF protection while allowing top-level navigation
 * - Path=/: Applies to all paths
 *
 * If the cookie name starts with __Host-, the Domain attribute is omitted
 * and Path must be / (per cookie prefixes spec).
 *
 * @param cookieName - Name of the session cookie
 * @param sessionId - Session identifier value
 * @param maxAgeSeconds - Cookie max age in seconds
 * @param domain - Cookie domain (optional, ignored for __Host- prefix)
 * @returns Set-Cookie header value
 */
function buildSessionCookieHeader(
    cookieName: string,
    sessionId: string,
    maxAgeSeconds: number,
    domain?: string
): string {
    const parts = [
        `${cookieName}=${sessionId}`,
        `Max-Age=${maxAgeSeconds}`,
        'Path=/',
        'HttpOnly',
        'Secure',
        'SameSite=Lax',
    ];

    // __Host- prefix requires no Domain attribute
    if (domain && !cookieName.startsWith('__Host-')) {
        parts.push(`Domain=${domain}`);
    }

    return parts.join('; ');
}

// =============================================================================
// Response Helpers
// =============================================================================

/**
 * Return an authorization error using the appropriate response mode.
 */
function authErrorResponse(
    redirectUri: string,
    errorCode: string,
    description: string,
    state: string | undefined,
    issuer: string,
    responseMode?: 'query' | 'fragment' | 'form_post'
): APIGatewayProxyResultV2 {
    if (responseMode === 'form_post') {
        return formPostError(redirectUri, errorCode, description, state, issuer);
    }

    // Default to query string for code flow
    const url = new URL(redirectUri);
    url.searchParams.set('error', errorCode);
    url.searchParams.set('error_description', description);
    url.searchParams.set('iss', issuer);
    if (state) {
        url.searchParams.set('state', state);
    }
    return redirect(url.toString());
}

/**
 * Return a successful authorization response using the appropriate response mode.
 */
function authSuccessResponse(
    redirectUri: string,
    code: string,
    state: string | undefined,
    issuer: string,
    responseMode?: 'query' | 'fragment' | 'form_post',
    setCookieHeader?: string
): APIGatewayProxyResultV2 {
    const params: Record<string, string> = {
        code,
        iss: issuer,
    };

    if (state) {
        params.state = state;
    }

    if (responseMode === 'form_post') {
        const response = formPostResponse(redirectUri, params);
        if (setCookieHeader && response.headers) {
            (response.headers as Record<string, string>)['Set-Cookie'] = setCookieHeader;
        }
        return response;
    }

    // Default to query string for code flow
    const url = new URL(redirectUri);
    url.searchParams.set('code', code);
    url.searchParams.set('iss', issuer);
    if (state) {
        url.searchParams.set('state', state);
    }

    const headers: Record<string, string> = {
        Location: url.toString(),
        'Cache-Control': 'no-store',
        'Pragma': 'no-cache',
    };

    if (setCookieHeader) {
        headers['Set-Cookie'] = setCookieHeader;
    }

    return {
        statusCode: 302,
        headers,
        body: '',
    };
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
        logger.info('Authorization callback received', { path: event.requestContext.http.path });

        // Step 1: Validate session_id parameter
        const sessionId = event.queryStringParameters?.session_id;

        if (!sessionId) {
            logger.warn('Missing session_id parameter');
            return invalidRequest('Missing required parameter: session_id');
        }

        const config = getEnvConfig();
        const client = getDocClient();

        // Step 2: Fetch session
        const sessionResult = await client.send(
            new GetCommand({
                TableName: config.tableName,
                Key: { PK: `SESSION#${sessionId}`, SK: 'METADATA' },
            })
        );

        if (!sessionResult.Item) {
            logger.warn('Session not found', { sessionId });
            return invalidRequest('Invalid or expired session');
        }

        const session = sessionResult.Item as LoginSessionItem;

        // Step 3: Validate redirect_uri exists before any redirects
        if (!session.redirectUri) {
            logger.error('Session missing redirect_uri', { sessionId });
            return invalidRequest('Invalid session state');
        }

        // Step 4: Check session expiration
        const nowEpochSeconds = Math.floor(Date.now() / 1000);
        if (session.ttl && session.ttl < nowEpochSeconds) {
            logger.warn('Session expired', { sessionId, ttl: session.ttl, now: nowEpochSeconds });
            return authErrorResponse(
                session.redirectUri,
                'access_denied',
                'Session has expired',
                session.state,
                config.issuer,
                session.responseMode
            );
        }

        // Step 5: Verify user authentication
        if (!session.authenticatedUserId ||
            typeof session.authenticatedUserId !== 'string' ||
            session.authenticatedUserId.trim().length === 0) {
            logger.warn('Session not authenticated', { sessionId });
            return authErrorResponse(
                session.redirectUri,
                'access_denied',
                'User authentication required',
                session.state,
                config.issuer,
                session.responseMode
            );
        }

        // Step 6: Validate required session fields
        if (!session.codeChallenge || !session.codeChallengeMethod || !session.clientId) {
            logger.error('Session missing required fields', {
                sessionId,
                hasCodeChallenge: !!session.codeChallenge,
                hasClientId: !!session.clientId,
            });
            return serverError('Invalid session state');
        }

        // Step 7: Generate authorization code
        const code = generateAuthorizationCode();
        const now = new Date().toISOString();
        const codeTtlEpochSeconds = nowEpochSeconds + config.codeTtlSeconds;

        const authCode: AuthCodeItem = {
            PK: `CODE#${code}`,
            SK: 'METADATA',
            GSI1PK: `CLIENT#${session.clientId}`,
            GSI1SK: `CODE#${now}`,
            ttl: codeTtlEpochSeconds,
            entityType: 'AUTH_CODE',
            createdAt: now,
            updatedAt: now,
            code,
            codeChallenge: session.codeChallenge,
            codeChallengeMethod: 'S256',
            clientId: session.clientId,
            sub: session.authenticatedUserId,
            scope: session.scope,
            redirectUri: session.redirectUri,
            nonce: session.nonce,
            used: false,
            issuedAt: now,
        };

        // Step 8: Store authorization code (atomic with collision check)
        try {
            await client.send(
                new PutCommand({
                    TableName: config.tableName,
                    Item: authCode,
                    ConditionExpression: 'attribute_not_exists(PK)',
                })
            );
        } catch (putError) {
            if ((putError as Error).name === 'ConditionalCheckFailedException') {
                logger.warn('Authorization code collision detected', { sessionId });
                return serverError('Please retry the authorization request');
            }
            throw putError;
        }

        // Step 9: Delete session (single-use)
        try {
            await client.send(
                new DeleteCommand({
                    TableName: config.tableName,
                    Key: { PK: `SESSION#${sessionId}`, SK: 'METADATA' },
                    ConditionExpression: 'attribute_exists(PK)',
                })
            );
        } catch (deleteError) {
            if ((deleteError as Error).name === 'ConditionalCheckFailedException') {
                logger.warn('Session already deleted during callback', { sessionId });
            } else {
                throw deleteError;
            }
        }

        // Step 10: Create authenticated user session for prompt=none support
        const authSessionId = randomUUID();
        const authSessionTtlEpochSeconds = nowEpochSeconds + config.authSessionTtlSeconds;

        const authSession: AuthenticatedSessionItem = {
            PK: `AUTH_SESSION#${authSessionId}`,
            SK: 'METADATA',
            GSI1PK: `USER#${session.authenticatedUserId}`,
            GSI1SK: `AUTH_SESSION#${now}`,
            ttl: authSessionTtlEpochSeconds,
            entityType: 'AUTH_SESSION',
            createdAt: now,
            updatedAt: now,
            sessionId: authSessionId,
            sub: session.authenticatedUserId,
            authenticatedAt: session.authenticatedAt || now,
            authMethod: session.authMethod || 'password',
            clientId: session.clientId,
            userAgent: event.requestContext.http.userAgent,
            ipAddress: event.requestContext.http.sourceIp,
            lastActivityAt: now,
        };

        await client.send(
            new PutCommand({
                TableName: config.tableName,
                Item: authSession,
            })
        );

        logger.info('Authenticated session created', {
            authSessionId,
            sub: session.authenticatedUserId,
            ttlSeconds: config.authSessionTtlSeconds,
        });

        // Build session cookie
        const sessionCookie = buildSessionCookieHeader(
            config.sessionCookieName,
            authSessionId,
            config.authSessionTtlSeconds,
            config.sessionCookieDomain
        );

        // Step 11: Audit logging
        logger.info('Authorization code issued', {
            clientId: session.clientId,
            sub: session.authenticatedUserId,
            sessionId,
            authSessionId,
            responseMode: session.responseMode || 'query',
        });

        auditLogger.authCodeIssued(
            { type: 'USER', sub: session.authenticatedUserId },
            {
                clientId: session.clientId,
                scopes: session.scope.split(' '),
                expiresAt: new Date(codeTtlEpochSeconds * 1000).toISOString(),
            }
        );

        // Step 12: Return authorization response with session cookie
        return authSuccessResponse(
            session.redirectUri,
            code,
            session.state,
            config.issuer,
            session.responseMode,
            sessionCookie
        );
    } catch (err) {
        const e = err as Error;
        logger.error('Authorization callback error', { error: e.message, stack: e.stack });
        return serverError('An unexpected error occurred');
    }
};
