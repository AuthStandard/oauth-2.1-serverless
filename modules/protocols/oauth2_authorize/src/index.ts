/**
 * OAuth 2.1 Authorization Endpoint - Lambda Handler
 *
 * Implements GET /authorize per OAuth 2.1 (draft-ietf-oauth-v2-1-14) Section 4.1.1.
 *
 * Flow:
 * 1. Check for duplicate parameters (OAuth 2.1 Section 3.1)
 * 2. Validate required parameters (client_id, response_type, code_challenge)
 * 3. Fetch client configuration from DynamoDB
 * 4. Validate redirect_uri against registered URIs (strict equality)
 * 5. Handle prompt=none for silent authentication
 * 6. Create login session with PKCE challenge and OIDC parameters
 * 7. Redirect to authentication router
 *
 * Security:
 * - Mandatory PKCE with S256 only (OAuth 2.1 Section 4.1.1)
 * - Strict redirect_uri validation (exact match per Section 2.3.1)
 * - Duplicate parameter rejection (Section 3.1)
 * - Session TTL prevents fixation attacks
 * - Client validation before redirect prevents open redirector attacks
 *
 * @module oauth2_authorize
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-14#section-4.1.1
 * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
 */

import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2, Context } from 'aws-lambda';
import { randomUUID, randomBytes } from 'node:crypto';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import {
    createLogger,
    withContext,
    invalidRequest,
    serverError,
    redirect,
    formPostError,
    formPostResponse,
} from '@oauth-server/shared';
import { validateAuthorizationParams } from './validator';
import type { AuthorizeEnvConfig, ClientItem, LoginSessionItem, AuthenticatedSessionItem } from './types';

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

function getEnvConfig(): AuthorizeEnvConfig {
    const tableName = process.env.TABLE_NAME;
    const loginRouterUrl = process.env.LOGIN_ROUTER_URL;
    const sessionTtlSecondsStr = process.env.SESSION_TTL_SECONDS;
    const issuer = process.env.ISSUER;
    const sessionCookieName = process.env.SESSION_COOKIE_NAME || '__Host-sid';

    if (!tableName) throw new Error('TABLE_NAME environment variable is required');
    if (!loginRouterUrl) throw new Error('LOGIN_ROUTER_URL environment variable is required');
    if (!sessionTtlSecondsStr) throw new Error('SESSION_TTL_SECONDS environment variable is required');
    if (!issuer) throw new Error('ISSUER environment variable is required');

    const sessionTtlSeconds = parseInt(sessionTtlSecondsStr, 10);
    if (isNaN(sessionTtlSeconds) || sessionTtlSeconds <= 0) {
        throw new Error('SESSION_TTL_SECONDS must be a positive integer');
    }

    return { tableName, loginRouterUrl, sessionTtlSeconds, issuer, sessionCookieName };
}

// =============================================================================
// Request Parsing
// =============================================================================

interface RawAuthorizeParams {
    clientId?: string;
    responseType?: 'code';
    redirectUri?: string;
    scope?: string;
    state?: string;
    codeChallenge?: string;
    codeChallengeMethod?: 'S256';
    nonce?: string;
    responseMode?: 'query' | 'fragment' | 'form_post';
    prompt?: 'none' | 'login' | 'consent' | 'select_account';
    loginHint?: string;
    maxAge?: string;
    uiLocales?: string;
    acrValues?: string;
}

function parseQueryParams(event: APIGatewayProxyEventV2): RawAuthorizeParams {
    const q = event.queryStringParameters || {};

    return {
        clientId: q.client_id,
        responseType: q.response_type as 'code' | undefined,
        redirectUri: q.redirect_uri,
        scope: q.scope || 'openid',
        state: q.state,
        codeChallenge: q.code_challenge,
        codeChallengeMethod: (q.code_challenge_method || 'S256') as 'S256',
        nonce: q.nonce,
        responseMode: q.response_mode as 'query' | 'fragment' | 'form_post' | undefined,
        prompt: q.prompt as 'none' | 'login' | 'consent' | 'select_account' | undefined,
        loginHint: q.login_hint,
        maxAge: q.max_age,
        uiLocales: q.ui_locales,
        acrValues: q.acr_values,
    };
}

// =============================================================================
// Error Response Helpers
// =============================================================================

/**
 * Return an authorization error using the appropriate response mode.
 */
function authError(
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

// =============================================================================
// Session Cookie Helpers
// =============================================================================

/**
 * Parse cookies from the Cookie header.
 *
 * @param cookieHeader - The Cookie header value
 * @returns Map of cookie name to value
 */
function parseCookies(cookieHeader: string | undefined): Map<string, string> {
    const cookies = new Map<string, string>();
    if (!cookieHeader) return cookies;

    const pairs = cookieHeader.split(';');
    for (const pair of pairs) {
        const [name, ...valueParts] = pair.trim().split('=');
        if (name) {
            cookies.set(name, valueParts.join('='));
        }
    }
    return cookies;
}

/**
 * Get the session ID from the session cookie.
 *
 * @param event - API Gateway event
 * @param cookieName - Name of the session cookie
 * @returns Session ID or undefined
 */
function getSessionIdFromCookie(event: APIGatewayProxyEventV2, cookieName: string): string | undefined {
    const cookieHeader = event.cookies?.join('; ') || event.headers?.cookie;
    const cookies = parseCookies(cookieHeader);
    return cookies.get(cookieName);
}

/**
 * Fetch and validate an authenticated session from DynamoDB.
 *
 * @param client - DynamoDB Document client
 * @param tableName - DynamoDB table name
 * @param sessionId - Session ID from cookie
 * @returns Authenticated session or null if invalid/expired
 */
async function getAuthenticatedSession(
    client: DynamoDBDocumentClient,
    tableName: string,
    sessionId: string
): Promise<AuthenticatedSessionItem | null> {
    const result = await client.send(
        new GetCommand({
            TableName: tableName,
            Key: { PK: `AUTH_SESSION#${sessionId}`, SK: 'METADATA' },
        })
    );

    if (!result.Item) return null;

    const session = result.Item as AuthenticatedSessionItem;

    // Check TTL expiration
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    if (session.ttl && session.ttl < nowEpochSeconds) {
        return null;
    }

    return session;
}

/**
 * Generate a cryptographically secure authorization code.
 *
 * Uses 256 bits of entropy (32 bytes) which exceeds NIST SP 800-63B
 * requirements for authorization codes.
 *
 * @returns Base64url-encoded authorization code
 */
function generateAuthorizationCode(): string {
    return randomBytes(AUTH_CODE_BYTES)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

/**
 * Return a successful authorization response for silent auth (prompt=none).
 */
function authSuccessResponse(
    redirectUri: string,
    code: string,
    state: string | undefined,
    issuer: string,
    responseMode?: 'query' | 'fragment' | 'form_post'
): APIGatewayProxyResultV2 {
    const params: Record<string, string> = {
        code,
        iss: issuer,
    };

    if (state) {
        params.state = state;
    }

    if (responseMode === 'form_post') {
        return formPostResponse(redirectUri, params);
    }

    // Default to query string for code flow
    const url = new URL(redirectUri);
    url.searchParams.set('code', code);
    url.searchParams.set('iss', issuer);
    if (state) {
        url.searchParams.set('state', state);
    }
    return redirect(url.toString());
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
        logger.info('Authorization request received', { path: event.requestContext.http.path });

        // Step 1: Parse and validate parameters (includes duplicate check)
        const rawParams = parseQueryParams(event);
        const validation = validateAuthorizationParams(rawParams, event);

        if (!validation.valid) {
            logger.warn('Authorization request validation failed', { error: 'invalid_request' });
            return validation.error;
        }

        const params = validation.params;
        const config = getEnvConfig();
        const client = getDocClient();

        // Step 2: Fetch client configuration
        const clientResult = await client.send(
            new GetCommand({
                TableName: config.tableName,
                Key: { PK: `CLIENT#${params.clientId}`, SK: 'CONFIG' },
            })
        );

        if (!clientResult.Item) {
            logger.warn('Client not found', { clientId: params.clientId });
            return invalidRequest(`Unknown client_id: ${params.clientId}`);
        }

        const clientConfig = clientResult.Item as ClientItem;

        // Step 3: Validate redirect_uri (strict equality per OAuth 2.1 Section 2.3.1)
        if (!clientConfig.redirectUris.includes(params.redirectUri)) {
            logger.warn('Redirect URI mismatch', {
                clientId: params.clientId,
                providedUri: params.redirectUri,
            });
            return invalidRequest('redirect_uri does not match any registered URIs');
        }

        // Step 4: Handle prompt=none (silent authentication)
        // Per OIDC Core 1.0 Section 3.1.2.1:
        // "If the End-User is already authenticated, the Authorization Server
        // MUST NOT display any authentication or consent UI."
        if (params.prompt === 'none') {
            logger.info('prompt=none requested - checking for existing session');

            // Check for session cookie
            const authSessionId = getSessionIdFromCookie(event, config.sessionCookieName);
            if (!authSessionId) {
                logger.info('No session cookie found for prompt=none');
                return authError(
                    params.redirectUri,
                    'login_required',
                    'User authentication is required',
                    params.state,
                    config.issuer,
                    params.responseMode
                );
            }

            // Validate the authenticated session
            const authSession = await getAuthenticatedSession(client, config.tableName, authSessionId);
            if (!authSession) {
                logger.info('Session cookie invalid or expired for prompt=none', { authSessionId });
                return authError(
                    params.redirectUri,
                    'login_required',
                    'User authentication is required',
                    params.state,
                    config.issuer,
                    params.responseMode
                );
            }

            // Check max_age if specified
            if (params.maxAge !== undefined) {
                const authTime = new Date(authSession.authenticatedAt).getTime() / 1000;
                const nowSeconds = Math.floor(Date.now() / 1000);
                const authAge = nowSeconds - authTime;

                if (authAge > params.maxAge) {
                    logger.info('Session too old for max_age requirement', {
                        authAge,
                        maxAge: params.maxAge,
                    });
                    return authError(
                        params.redirectUri,
                        'login_required',
                        'User authentication has exceeded max_age',
                        params.state,
                        config.issuer,
                        params.responseMode
                    );
                }
            }

            // User is authenticated - issue authorization code directly
            logger.info('Silent auth successful', {
                sub: authSession.sub,
                authSessionId,
            });

            // Generate authorization code using the same method as callback handler
            const code = generateAuthorizationCode();
            const now = new Date().toISOString();
            const nowEpochSeconds = Math.floor(Date.now() / 1000);
            const codeTtlSeconds = parseInt(process.env.CODE_TTL_SECONDS || '600', 10);
            const codeTtlEpochSeconds = nowEpochSeconds + codeTtlSeconds;

            const authCode = {
                PK: `CODE#${code}`,
                SK: 'METADATA',
                GSI1PK: `CLIENT#${params.clientId}`,
                GSI1SK: `CODE#${now}`,
                ttl: codeTtlEpochSeconds,
                entityType: 'AUTH_CODE',
                createdAt: now,
                updatedAt: now,
                code,
                codeChallenge: params.codeChallenge,
                codeChallengeMethod: 'S256' as const,
                clientId: params.clientId,
                sub: authSession.sub,
                scope: params.scope,
                redirectUri: params.redirectUri,
                nonce: params.nonce,
                used: false,
                issuedAt: now,
            };

            await client.send(
                new PutCommand({
                    TableName: config.tableName,
                    Item: authCode,
                })
            );

            auditLogger.authCodeIssued(
                { type: 'USER', sub: authSession.sub },
                {
                    clientId: params.clientId,
                    scopes: params.scope.split(' '),
                    expiresAt: new Date(codeTtlEpochSeconds * 1000).toISOString(),
                }
            );

            return authSuccessResponse(
                params.redirectUri,
                code,
                params.state,
                config.issuer,
                params.responseMode
            );
        }

        // Step 5: Create login session
        const sessionId = randomUUID();
        const now = new Date().toISOString();
        const ttlEpochSeconds = Math.floor(Date.now() / 1000) + config.sessionTtlSeconds;

        const session: LoginSessionItem = {
            PK: `SESSION#${sessionId}`,
            SK: 'METADATA',
            GSI1PK: `CLIENT#${params.clientId}`,
            GSI1SK: `SESSION#${now}`,
            ttl: ttlEpochSeconds,
            entityType: 'LOGIN_SESSION',
            createdAt: now,
            updatedAt: now,
            sessionId,
            clientId: params.clientId,
            scope: params.scope,
            codeChallenge: params.codeChallenge,
            codeChallengeMethod: 'S256',
            redirectUri: params.redirectUri,
            state: params.state,
            nonce: params.nonce,
            responseType: 'code',
            authStrategyId: clientConfig.authStrategyId,
            // OIDC extension parameters
            responseMode: params.responseMode,
            prompt: params.prompt,
            loginHint: params.loginHint,
            maxAge: params.maxAge,
            uiLocales: params.uiLocales,
            acrValues: params.acrValues,
        };

        await client.send(
            new PutCommand({
                TableName: config.tableName,
                Item: session,
            })
        );

        logger.info('Login session created', { sessionId, clientId: params.clientId });

        auditLogger.authSessionCreated(
            { type: 'CLIENT', clientId: params.clientId },
            {
                sessionId,
                scope: params.scope,
                redirectUri: params.redirectUri,
            }
        );

        // Step 6: Redirect to login router
        let redirectUrl: string;
        if (config.loginRouterUrl.startsWith('http://') || config.loginRouterUrl.startsWith('https://')) {
            const loginUrl = new URL(config.loginRouterUrl);
            loginUrl.searchParams.set('session_id', sessionId);
            // Pass login_hint to the login router if provided
            if (params.loginHint) {
                loginUrl.searchParams.set('login_hint', params.loginHint);
            }
            // Pass prompt to indicate if re-auth is required
            if (params.prompt === 'login') {
                loginUrl.searchParams.set('force_login', 'true');
            }
            redirectUrl = loginUrl.toString();
        } else {
            const separator = config.loginRouterUrl.includes('?') ? '&' : '?';
            let queryParams = `session_id=${encodeURIComponent(sessionId)}`;
            if (params.loginHint) {
                queryParams += `&login_hint=${encodeURIComponent(params.loginHint)}`;
            }
            if (params.prompt === 'login') {
                queryParams += '&force_login=true';
            }
            redirectUrl = `${config.loginRouterUrl}${separator}${queryParams}`;
        }

        return redirect(redirectUrl);
    } catch (err) {
        const e = err as Error;
        logger.error('Authorization endpoint error', { error: e.message, stack: e.stack });
        return serverError('An unexpected error occurred');
    }
};
