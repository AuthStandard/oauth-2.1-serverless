/**
 * OAuth 2.1 Authorization Code Grant Handler
 *
 * Implements OAuth 2.1 Section 4.1.3 - Token Endpoint Extension.
 *
 * Flow:
 * 1. Validate required parameters (code, redirect_uri, code_verifier)
 * 2. Validate DPoP proof if present (RFC 9449)
 * 3. Fetch and validate authorization code from database
 * 4. Verify code hasn't been used (replay attack prevention)
 * 5. Authenticate client (confidential) or validate client_id (public)
 * 6. Verify redirect_uri matches original authorization request
 * 7. Verify PKCE code_verifier against stored code_challenge
 * 8. Mark code as used (atomic operation)
 * 9. Verify user is still active
 * 10. Generate tokens (access_token, id_token if openid, refresh_token if offline_access)
 *
 * Security Controls:
 * - Single-use authorization codes (Section 4.1.3)
 * - PKCE mandatory (Section 4.1.1)
 * - Redirect URI exact match (Section 2.3.1)
 * - Client binding verification
 * - DPoP sender-constrained tokens (RFC 9449)
 *
 * @module oauth2_token/grants/authorization-code
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-14#section-4.1.3
 * @see https://datatracker.ietf.org/doc/html/rfc9449
 */

import type { APIGatewayProxyResultV2 } from 'aws-lambda';
import type { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { GetCommand, UpdateCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import { createHash, randomUUID } from 'node:crypto';
import { verifyPkce, isValidCodeVerifier, hashToken, AuditLogger, Logger } from '@oauth-server/shared';
import { createSigner } from '../signer';
import { tokenResponse, errorResponse } from '../response';
import { authenticateClient } from '../client-auth';
import { handleDPoP, buildTokenEndpointUrl } from '../dpop-handler';
import { fetchUserGroups } from '../groups';
import type { TokenRequestParams, EnvConfig, AuthCodeItem, UserItem } from '../types';

// =============================================================================
// at_hash Computation (OpenID Connect Core Section 3.1.3.6)
// =============================================================================

/**
 * Compute at_hash claim for ID token.
 *
 * Per OpenID Connect Core Section 3.1.3.6:
 * - Hash the access token with SHA-256
 * - Take the left-most half of the hash
 * - Base64url encode the result
 *
 * @param accessToken - The access token to hash
 * @returns Base64url-encoded left half of SHA-256 hash
 */
function computeAtHash(accessToken: string): string {
    const hash = createHash('sha256').update(accessToken).digest();
    return hash
        .subarray(0, 16)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

// =============================================================================
// Grant Handler
// =============================================================================

/**
 * Handle authorization_code grant type.
 *
 * @param params - Parsed token request parameters
 * @param authHeader - Authorization header for client authentication
 * @param config - Environment configuration
 * @param client - DynamoDB document client
 * @param requestId - AWS request ID for tracing
 * @param ip - Client IP address for audit logging
 * @param dpopHeader - DPoP header value (optional, for sender-constrained tokens)
 * @returns Token response or error response
 */
export async function handleAuthorizationCodeGrant(
    params: TokenRequestParams,
    authHeader: string | undefined,
    config: EnvConfig,
    client: DynamoDBDocumentClient,
    requestId: string,
    ip: string,
    dpopHeader?: string
): Promise<APIGatewayProxyResultV2> {
    const log = new Logger(requestId);
    const audit = new AuditLogger({ requestId, ip });

    // -------------------------------------------------------------------------
    // Step 1: Parameter Validation (OAuth 2.1 Section 4.1.3)
    // -------------------------------------------------------------------------
    if (!params.code) {
        return errorResponse(400, 'invalid_request', 'Missing required parameter: code');
    }
    if (!params.redirectUri) {
        return errorResponse(400, 'invalid_request', 'Missing required parameter: redirect_uri');
    }
    if (!params.codeVerifier) {
        return errorResponse(400, 'invalid_request', 'Missing required parameter: code_verifier (PKCE is mandatory)');
    }
    if (!isValidCodeVerifier(params.codeVerifier)) {
        return errorResponse(400, 'invalid_request', 'Invalid code_verifier format');
    }

    // -------------------------------------------------------------------------
    // Step 2: DPoP Validation (RFC 9449)
    // -------------------------------------------------------------------------
    const dpopResult = await handleDPoP({
        dpopHeader,
        httpMethod: 'POST',
        tokenEndpointUrl: buildTokenEndpointUrl(config.issuer),
        tableName: config.tableName,
        dbClient: client,
        logger: log,
    });

    if (!dpopResult.valid) {
        return errorResponse(400, dpopResult.errorCode || 'invalid_dpop_proof', dpopResult.errorDescription);
    }

    // -------------------------------------------------------------------------
    // Step 3: Fetch Authorization Code
    // -------------------------------------------------------------------------
    const codeResult = await client.send(
        new GetCommand({
            TableName: config.tableName,
            Key: { PK: `CODE#${params.code}`, SK: 'METADATA' },
        })
    );

    if (!codeResult.Item) {
        log.warn('Authorization code not found');
        return errorResponse(400, 'invalid_grant', 'Authorization code is invalid or expired');
    }

    const authCode = codeResult.Item as AuthCodeItem;

    // Validate required fields exist
    if (!authCode.code || !authCode.clientId || !authCode.codeChallenge || !authCode.redirectUri || !authCode.sub) {
        log.error('Authorization code missing required fields');
        return errorResponse(400, 'invalid_grant', 'Authorization code is invalid');
    }

    // -------------------------------------------------------------------------
    // Step 3: Replay Attack Detection (OAuth 2.1 Section 4.1.3)
    // -------------------------------------------------------------------------
    if (authCode.used) {
        log.warn('Authorization code already used', { clientId: authCode.clientId });
        return errorResponse(400, 'invalid_grant', 'Authorization code has already been used');
    }

    // -------------------------------------------------------------------------
    // Step 4: Expiration Check
    // -------------------------------------------------------------------------
    const nowEpoch = Math.floor(Date.now() / 1000);
    if (!authCode.ttl || authCode.ttl < nowEpoch) {
        log.warn('Authorization code expired', { clientId: authCode.clientId });
        return errorResponse(400, 'invalid_grant', 'Authorization code has expired');
    }

    // -------------------------------------------------------------------------
    // Step 5: Client Authentication (OAuth 2.1 Section 3.2.1)
    // -------------------------------------------------------------------------
    const clientValidation = await authenticateClient(params, authHeader, client, config.tableName);
    if (!clientValidation.valid) {
        return clientValidation.error!;
    }

    const clientItem = clientValidation.clientItem!;

    // Verify code was issued to this client
    if (authCode.clientId !== clientItem.clientId) {
        log.warn('Client ID mismatch', { expected: authCode.clientId, actual: clientItem.clientId });
        return errorResponse(400, 'invalid_grant', 'Authorization code was not issued to this client');
    }

    // Verify client is authorized for this grant type
    if (!clientItem.grantTypes.includes('authorization_code')) {
        log.warn('Client not authorized for authorization_code grant', { clientId: clientItem.clientId });
        return errorResponse(401, 'unauthorized_client', 'Client is not authorized for this grant type');
    }

    // -------------------------------------------------------------------------
    // Step 6: Redirect URI Validation (OAuth 2.1 Section 2.3.1)
    // -------------------------------------------------------------------------
    if (authCode.redirectUri !== params.redirectUri) {
        log.warn('Redirect URI mismatch', { clientId: clientItem.clientId });
        return errorResponse(400, 'invalid_grant', 'redirect_uri does not match the original request');
    }

    // -------------------------------------------------------------------------
    // Step 7: PKCE Verification (OAuth 2.1 Section 4.1.3)
    // -------------------------------------------------------------------------
    if (!verifyPkce(params.codeVerifier, authCode.codeChallenge)) {
        log.warn('PKCE verification failed', { clientId: authCode.clientId });
        return errorResponse(400, 'invalid_grant', 'code_verifier is invalid');
    }

    // -------------------------------------------------------------------------
    // Step 8: Mark Code as Used (Atomic Operation)
    // -------------------------------------------------------------------------
    try {
        await client.send(
            new UpdateCommand({
                TableName: config.tableName,
                Key: { PK: `CODE#${params.code}`, SK: 'METADATA' },
                UpdateExpression: 'SET #used = :true, updatedAt = :now',
                ConditionExpression: '#used = :false AND attribute_exists(PK)',
                ExpressionAttributeNames: { '#used': 'used' },
                ExpressionAttributeValues: {
                    ':true': true,
                    ':false': false,
                    ':now': new Date().toISOString(),
                },
            })
        );
    } catch (updateError) {
        if ((updateError as Error).name === 'ConditionalCheckFailedException') {
            log.warn('Authorization code race condition');
            return errorResponse(400, 'invalid_grant', 'Authorization code has already been used');
        }
        throw updateError;
    }

    audit.authCodeExchanged({ type: 'USER', sub: authCode.sub }, { clientId: authCode.clientId, grantType: 'authorization_code' });

    // -------------------------------------------------------------------------
    // Step 9: User Verification
    // -------------------------------------------------------------------------
    const userResult = await client.send(
        new GetCommand({
            TableName: config.tableName,
            Key: { PK: `USER#${authCode.sub}`, SK: 'PROFILE' },
        })
    );

    const user = userResult.Item as UserItem | undefined;

    if (!user) {
        log.error('User not found', { sub: authCode.sub });
        return errorResponse(400, 'invalid_grant', 'User account not found');
    }

    if (user.status !== 'ACTIVE') {
        log.warn('User not active', { sub: authCode.sub, status: user.status });
        return errorResponse(400, 'invalid_grant', 'Authorization code is invalid or expired');
    }

    // -------------------------------------------------------------------------
    // Step 10: Token Generation
    // -------------------------------------------------------------------------
    const signer = createSigner();
    const jti = randomUUID();
    const authTime = Math.floor(new Date(authCode.issuedAt).getTime() / 1000);
    const accessTokenTtl = clientItem.tokenLifetimes?.accessToken || config.accessTokenTtl;
    const refreshTokenTtl = clientItem.tokenLifetimes?.refreshToken || config.refreshTokenTtl;

    // Fetch user's group memberships for RBAC claims
    const userGroups = await fetchUserGroups(authCode.sub, config.tableName, client);

    // Include DPoP thumbprint in access token if DPoP was used
    const accessToken = await signer.createAccessToken({
        issuer: config.issuer,
        sub: authCode.sub,
        clientId: authCode.clientId,
        scope: authCode.scope,
        audience: authCode.clientId,
        expiresIn: accessTokenTtl,
        jti,
        dpopThumbprint: dpopResult.thumbprint,
        groups: userGroups.length > 0 ? userGroups : undefined,
    });

    // ID Token (if openid scope requested)
    let idToken: string | undefined;
    if (authCode.scope.includes('openid')) {
        const name = user?.profile
            ? [user.profile.givenName, user.profile.familyName].filter(Boolean).join(' ')
            : undefined;
        const atHash = computeAtHash(accessToken);

        idToken = await signer.createIdToken({
            issuer: config.issuer,
            sub: authCode.sub,
            clientId: authCode.clientId,
            expiresIn: config.idTokenTtl,
            authTime,
            nonce: authCode.nonce,
            atHash,
            email: user?.email,
            emailVerified: user?.emailVerified,
            name: name || undefined,
        });
    }

    // Refresh Token (if offline_access scope requested)
    let refreshToken: string | undefined;
    if (authCode.scope.includes('offline_access')) {
        refreshToken = await signer.createRefreshToken({
            issuer: config.issuer,
            sub: authCode.sub,
            clientId: authCode.clientId,
            scope: authCode.scope,
            expiresIn: refreshTokenTtl,
        });

        const refreshTokenHash = hashToken(refreshToken);
        const now = new Date().toISOString();
        const familyId = randomUUID();

        // Store refresh token with DPoP binding if DPoP was used
        await client.send(
            new PutCommand({
                TableName: config.tableName,
                Item: {
                    PK: `REFRESH#${refreshTokenHash}`,
                    SK: 'METADATA',
                    GSI1PK: `USER#${authCode.sub}`,
                    GSI1SK: `REFRESH#${now}`,
                    GSI2PK: `FAMILY#${familyId}`,
                    GSI2SK: `REFRESH#${now}`,
                    ttl: Math.floor(Date.now() / 1000) + refreshTokenTtl,
                    entityType: 'REFRESH_TOKEN',
                    createdAt: now,
                    updatedAt: now,
                    tokenHash: refreshTokenHash,
                    familyId,
                    rotated: false,
                    clientId: authCode.clientId,
                    sub: authCode.sub,
                    scope: authCode.scope,
                    issuedAt: now,
                    // DPoP binding - if set, refresh requests must use same key
                    ...(dpopResult.thumbprint && { dpopJkt: dpopResult.thumbprint }),
                },
            })
        );
    }

    // Audit token issuance
    const expiresAt = new Date(Date.now() + accessTokenTtl * 1000).toISOString();
    audit.tokenIssued(
        { type: 'USER', sub: authCode.sub },
        {
            tokenType: 'access_token',
            clientId: authCode.clientId,
            scopes: authCode.scope.split(' '),
            expiresAt,
            grantType: 'authorization_code',
            ...(dpopResult.dpopUsed && { dpopBound: true }),
        }
    );

    log.info('Tokens issued', {
        clientId: authCode.clientId,
        sub: authCode.sub,
        hasIdToken: !!idToken,
        hasRefreshToken: !!refreshToken,
        dpopBound: dpopResult.dpopUsed,
    });

    // -------------------------------------------------------------------------
    // Step 11: Build Response (OAuth 2.1 Section 3.2.3, RFC 9449 Section 5)
    // -------------------------------------------------------------------------
    const tokenType = dpopResult.dpopUsed ? 'DPoP' : 'Bearer';
    const response: Record<string, unknown> = {
        access_token: accessToken,
        token_type: tokenType,
        expires_in: accessTokenTtl,
        scope: authCode.scope,
    };
    if (idToken) response.id_token = idToken;
    if (refreshToken) response.refresh_token = refreshToken;

    return tokenResponse(response);
}
