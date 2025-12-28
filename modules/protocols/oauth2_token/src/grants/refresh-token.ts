/**
 * OAuth 2.1 Refresh Token Grant Handler
 *
 * Implements OAuth 2.1 Section 4.3 with mandatory refresh token rotation.
 *
 * Flow:
 * 1. Validate refresh_token parameter present
 * 2. Validate DPoP proof if present (RFC 9449)
 * 3. Fetch refresh token from database (by hash)
 * 4. Detect token reuse (replay attack) - revoke entire family if detected
 * 5. Verify token not expired
 * 6. Fetch and validate client configuration
 * 7. Authenticate confidential clients
 * 8. Validate DPoP key binding (if token was DPoP-bound)
 * 9. Validate scope downscoping (if requested)
 * 10. Verify user is still active
 * 11. Generate new tokens with rotation
 * 12. Mark old token as rotated (atomic)
 * 13. Store new refresh token
 *
 * Security Features:
 * - Mandatory token rotation (OAuth 2.1 Section 4.3.1)
 * - Token family tracking for replay attack detection
 * - Automatic family revocation on reuse detection
 * - Scope downscoping support (cannot exceed original grant)
 * - DPoP key binding validation (RFC 9449)
 *
 * @module oauth2_token/grants/refresh-token
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-14#section-4.3
 * @see https://datatracker.ietf.org/doc/html/rfc9449
 */

import type { APIGatewayProxyResultV2 } from 'aws-lambda';
import type { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { GetCommand, PutCommand, UpdateCommand, QueryCommand } from '@aws-sdk/lib-dynamodb';
import { randomUUID } from 'node:crypto';
import { hashToken, AuditLogger, Logger } from '@oauth-server/shared';
import { createSigner } from '../signer';
import { tokenResponse, errorResponse } from '../response';
import { validateScopeDownscope } from '../scope';
import { authenticateClient } from '../client-auth';
import { handleDPoP, buildTokenEndpointUrl } from '../dpop-handler';
import { fetchUserGroups } from '../groups';
import type { TokenRequestParams, EnvConfig, RefreshTokenItem, ClientItem, UserItem } from '../types';

// =============================================================================
// Token Family Revocation
// =============================================================================

/**
 * Revoke all tokens in a token family.
 *
 * Called when token reuse is detected (potential replay attack).
 * Per OAuth 2.1 Section 4.3.1, when a rotated token is reused,
 * the entire family should be revoked to stop the attack.
 *
 * @param dbClient - DynamoDB document client
 * @param tableName - DynamoDB table name
 * @param familyId - Token family identifier
 * @param log - Logger instance
 */
async function revokeTokenFamily(
    dbClient: DynamoDBDocumentClient,
    tableName: string,
    familyId: string,
    log: Logger
): Promise<void> {
    // Query all tokens in the family
    const result = await dbClient.send(
        new QueryCommand({
            TableName: tableName,
            IndexName: 'GSI2',
            KeyConditionExpression: 'GSI2PK = :pk',
            ExpressionAttributeValues: { ':pk': `FAMILY#${familyId}` },
        })
    );

    if (!result.Items || result.Items.length === 0) {
        return;
    }

    const now = new Date().toISOString();
    let revokedCount = 0;

    // Revoke each non-rotated token in the family
    for (const item of result.Items) {
        const token = item as RefreshTokenItem;
        if (!token.rotated) {
            try {
                await dbClient.send(
                    new UpdateCommand({
                        TableName: tableName,
                        Key: { PK: token.PK, SK: 'METADATA' },
                        UpdateExpression: 'SET rotated = :true, rotatedAt = :now, updatedAt = :now, revokedReason = :reason',
                        ConditionExpression: 'rotated = :false',
                        ExpressionAttributeValues: {
                            ':true': true,
                            ':false': false,
                            ':now': now,
                            ':reason': 'family_revocation_token_reuse',
                        },
                    })
                );
                revokedCount++;
            } catch {
                // Ignore ConditionalCheckFailedException - token already rotated
            }
        }
    }

    log.info('Token family revoked due to reuse detection', { familyId, tokensRevoked: revokedCount });
}

// =============================================================================
// Grant Handler
// =============================================================================

/**
 * Handle refresh_token grant type.
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
export async function handleRefreshTokenGrant(
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
    // Step 1: Parameter Validation
    // -------------------------------------------------------------------------
    if (!params.refreshToken) {
        return errorResponse(400, 'invalid_request', 'Missing required parameter: refresh_token');
    }

    const tokenHash = hashToken(params.refreshToken);

    // -------------------------------------------------------------------------
    // Step 2: Fetch Refresh Token (before DPoP validation to get binding info)
    // -------------------------------------------------------------------------
    const tokenResult = await client.send(
        new GetCommand({
            TableName: config.tableName,
            Key: { PK: `REFRESH#${tokenHash}`, SK: 'METADATA' },
        })
    );

    if (!tokenResult.Item) {
        log.warn('Refresh token not found');
        return errorResponse(400, 'invalid_grant', 'Refresh token is invalid or expired');
    }

    const refreshTokenItem = tokenResult.Item as RefreshTokenItem;

    // -------------------------------------------------------------------------
    // Step 3: DPoP Validation (RFC 9449)
    // If the original token was DPoP-bound, the refresh must use the same key
    // -------------------------------------------------------------------------
    const dpopResult = await handleDPoP({
        dpopHeader,
        httpMethod: 'POST',
        tokenEndpointUrl: buildTokenEndpointUrl(config.issuer),
        tableName: config.tableName,
        dbClient: client,
        logger: log,
        expectedThumbprint: refreshTokenItem.dpopJkt,
    });

    if (!dpopResult.valid) {
        return errorResponse(400, dpopResult.errorCode || 'invalid_dpop_proof', dpopResult.errorDescription);
    }

    // -------------------------------------------------------------------------
    // Step 4: Token Reuse Detection (Replay Attack Prevention)
    // Per OAuth 2.1 Section 4.3.1, if a rotated token is reused,
    // revoke the entire token family
    // -------------------------------------------------------------------------
    if (refreshTokenItem.rotated) {
        log.warn('Refresh token reuse detected - revoking family', {
            familyId: refreshTokenItem.familyId,
            clientId: refreshTokenItem.clientId,
            sub: refreshTokenItem.sub,
        });

        await revokeTokenFamily(client, config.tableName, refreshTokenItem.familyId, log);

        audit.tokenRevoked(
            { type: 'USER', sub: refreshTokenItem.sub },
            { tokenType: 'refresh_token', reason: 'rotation' }
        );

        return errorResponse(400, 'invalid_grant', 'Refresh token has been revoked');
    }

    // -------------------------------------------------------------------------
    // Step 4: Expiration Check
    // -------------------------------------------------------------------------
    const nowEpoch = Math.floor(Date.now() / 1000);
    if (!refreshTokenItem.ttl || refreshTokenItem.ttl < nowEpoch) {
        log.warn('Refresh token expired', { clientId: refreshTokenItem.clientId });
        return errorResponse(400, 'invalid_grant', 'Refresh token has expired');
    }

    // -------------------------------------------------------------------------
    // Step 5: Fetch Client Configuration
    // -------------------------------------------------------------------------
    const clientResult = await client.send(
        new GetCommand({
            TableName: config.tableName,
            Key: { PK: `CLIENT#${refreshTokenItem.clientId}`, SK: 'CONFIG' },
        })
    );

    if (!clientResult.Item) {
        log.warn('Client not found for refresh token', { clientId: refreshTokenItem.clientId });
        return errorResponse(400, 'invalid_grant', 'Refresh token is invalid');
    }

    const clientItem = clientResult.Item as ClientItem;

    // Verify grant type allowed
    if (!clientItem.grantTypes.includes('refresh_token')) {
        log.warn('Client not authorized for refresh_token grant', { clientId: clientItem.clientId });
        return errorResponse(401, 'unauthorized_client', 'Client is not authorized for this grant type');
    }

    // -------------------------------------------------------------------------
    // Step 6: Client Authentication (OAuth 2.1 Section 4.3.1)
    // Confidential clients MUST authenticate
    // -------------------------------------------------------------------------
    if (clientItem.clientType === 'CONFIDENTIAL') {
        const clientAuth = await authenticateClient(params, authHeader, client, config.tableName);
        if (!clientAuth.valid) {
            return clientAuth.error!;
        }
        if (clientAuth.clientItem!.clientId !== refreshTokenItem.clientId) {
            log.warn('Client mismatch for refresh token', { expected: refreshTokenItem.clientId });
            return errorResponse(400, 'invalid_grant', 'Refresh token was not issued to this client');
        }
    } else if (params.clientId && params.clientId !== refreshTokenItem.clientId) {
        // Public clients: validate client_id if provided
        log.warn('Client ID mismatch for refresh token', { expected: refreshTokenItem.clientId, actual: params.clientId });
        return errorResponse(400, 'invalid_grant', 'Refresh token was not issued to this client');
    }

    // -------------------------------------------------------------------------
    // Step 7: Validate Scope (OAuth 2.1 Section 4.3.1)
    // Requested scope MUST NOT exceed original grant
    // -------------------------------------------------------------------------
    const scopeValidation = validateScopeDownscope(params.scope, refreshTokenItem.scope);
    if (!scopeValidation.valid) {
        return scopeValidation.error;
    }
    const grantedScope = scopeValidation.scope;

    // -------------------------------------------------------------------------
    // Step 8: Verify User Still Active
    // -------------------------------------------------------------------------
    const userResult = await client.send(
        new GetCommand({
            TableName: config.tableName,
            Key: { PK: `USER#${refreshTokenItem.sub}`, SK: 'PROFILE' },
        })
    );

    if (!userResult.Item) {
        log.warn('User not found for refresh token', { sub: refreshTokenItem.sub });
        return errorResponse(400, 'invalid_grant', 'User account not found');
    }

    const user = userResult.Item as UserItem;

    if (user.status !== 'ACTIVE') {
        log.warn('User not active', { sub: refreshTokenItem.sub, status: user.status });
        return errorResponse(400, 'invalid_grant', 'Refresh token is invalid or expired');
    }

    // -------------------------------------------------------------------------
    // Step 9: Generate New Tokens
    // -------------------------------------------------------------------------
    const signer = createSigner();
    const jti = randomUUID();
    const now = new Date().toISOString();
    const accessTokenTtl = clientItem.tokenLifetimes?.accessToken || config.accessTokenTtl;
    const refreshTokenTtl = clientItem.tokenLifetimes?.refreshToken || config.refreshTokenTtl;

    // Determine DPoP thumbprint: use existing binding or new DPoP proof
    const dpopThumbprint = refreshTokenItem.dpopJkt || dpopResult.thumbprint;

    // Fetch user's group memberships for RBAC claims
    const userGroups = await fetchUserGroups(refreshTokenItem.sub, config.tableName, client);

    const accessToken = await signer.createAccessToken({
        issuer: config.issuer,
        sub: refreshTokenItem.sub,
        clientId: refreshTokenItem.clientId,
        scope: grantedScope,
        audience: refreshTokenItem.clientId,
        expiresIn: accessTokenTtl,
        jti,
        dpopThumbprint,
        groups: userGroups.length > 0 ? userGroups : undefined,
    });

    const newRefreshToken = await signer.createRefreshToken({
        issuer: config.issuer,
        sub: refreshTokenItem.sub,
        clientId: refreshTokenItem.clientId,
        scope: grantedScope,
        expiresIn: refreshTokenTtl,
    });

    const newTokenHash = hashToken(newRefreshToken);

    // -------------------------------------------------------------------------
    // Step 10: Mark Current Token as Rotated (Atomic Operation)
    // -------------------------------------------------------------------------
    try {
        await client.send(
            new UpdateCommand({
                TableName: config.tableName,
                Key: { PK: `REFRESH#${tokenHash}`, SK: 'METADATA' },
                UpdateExpression: 'SET rotated = :true, rotatedAt = :now, replacedByHash = :newHash, updatedAt = :now',
                ConditionExpression: 'rotated = :false AND attribute_exists(PK)',
                ExpressionAttributeValues: {
                    ':true': true,
                    ':false': false,
                    ':now': now,
                    ':newHash': newTokenHash,
                },
            })
        );
    } catch (updateError) {
        if ((updateError as Error).name === 'ConditionalCheckFailedException') {
            log.warn('Refresh token race condition');
            return errorResponse(400, 'invalid_grant', 'Refresh token has already been used');
        }
        throw updateError;
    }

    // -------------------------------------------------------------------------
    // Step 11: Store New Refresh Token (preserve DPoP binding)
    // -------------------------------------------------------------------------
    await client.send(
        new PutCommand({
            TableName: config.tableName,
            Item: {
                PK: `REFRESH#${newTokenHash}`,
                SK: 'METADATA',
                GSI1PK: `USER#${refreshTokenItem.sub}`,
                GSI1SK: `REFRESH#${now}`,
                GSI2PK: `FAMILY#${refreshTokenItem.familyId}`,
                GSI2SK: `REFRESH#${now}`,
                ttl: nowEpoch + refreshTokenTtl,
                entityType: 'REFRESH_TOKEN',
                createdAt: now,
                updatedAt: now,
                tokenHash: newTokenHash,
                familyId: refreshTokenItem.familyId,
                rotated: false,
                clientId: refreshTokenItem.clientId,
                sub: refreshTokenItem.sub,
                scope: grantedScope,
                issuedAt: now,
                // Preserve DPoP binding from original token
                ...(dpopThumbprint && { dpopJkt: dpopThumbprint }),
            },
        })
    );

    // Audit token refresh
    audit.tokenRefreshed(
        { type: 'USER', sub: refreshTokenItem.sub },
        {
            clientId: refreshTokenItem.clientId,
            scopes: grantedScope.split(' '),
            tokenRotated: true,
            ...(dpopThumbprint && { dpopBound: true }),
        }
    );

    log.info('Refresh token rotated', {
        clientId: refreshTokenItem.clientId,
        sub: refreshTokenItem.sub,
        familyId: refreshTokenItem.familyId,
        dpopBound: !!dpopThumbprint,
    });

    // -------------------------------------------------------------------------
    // Step 12: Build Response (OAuth 2.1 Section 4.3.2, RFC 9449 Section 5)
    // -------------------------------------------------------------------------
    const tokenType = dpopThumbprint ? 'DPoP' : 'Bearer';
    return tokenResponse({
        access_token: accessToken,
        token_type: tokenType,
        expires_in: accessTokenTtl,
        scope: grantedScope,
        refresh_token: newRefreshToken,
    });
}
