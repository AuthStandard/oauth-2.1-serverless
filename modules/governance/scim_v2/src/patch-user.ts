/**
 * SCIM v2 User Provisioning - PATCH /scim/v2/Users/{id}
 *
 * Updates a user per RFC 7644 Section 3.5.2.
 *
 * Supported Operations:
 * - replace active: Enable/disable user account
 *
 * Security Hook:
 * When active becomes false, queries REFRESH# GSI for this user
 * and batch deletes all refresh tokens to force re-authentication.
 *
 * @module governance/scim_v2/patch-user
 * @see RFC 7644 Section 3.5.2 - Modifying with PATCH
 */

import type { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { GetCommand, UpdateCommand, QueryCommand } from '@aws-sdk/lib-dynamodb';
import type { APIGatewayProxyResultV2 } from 'aws-lambda';
import { AuditLogger, Logger } from '@oauth-server/shared';
import type { UserItem } from '../../../shared_types/user';
import type { ScimPatchRequest, EnvConfig } from './types';
import { validatePatchRequest } from './validation';
import { userItemToScimUser, buildStatusUpdateParams } from './mapper';
import { scimUserResponse, scimBadRequest, scimNotFound } from './responses';

// =============================================================================
// Token Revocation
// =============================================================================

/**
 * Revoke all refresh tokens for a user.
 *
 * Called when user is deactivated to force re-authentication.
 * Uses GSI1 to efficiently query all user's refresh tokens.
 *
 * @param client - DynamoDB document client
 * @param tableName - DynamoDB table name
 * @param userId - User's sub identifier
 * @param log - Logger instance
 * @returns Number of tokens revoked
 */
async function revokeUserRefreshTokens(
    client: DynamoDBDocumentClient,
    tableName: string,
    userId: string,
    log: Logger
): Promise<number> {
    let revokedCount = 0;
    let lastEvaluatedKey: Record<string, unknown> | undefined;

    do {
        // Query all refresh tokens for this user using GSI1
        const result = await client.send(
            new QueryCommand({
                TableName: tableName,
                IndexName: 'GSI1',
                KeyConditionExpression: 'GSI1PK = :pk AND begins_with(GSI1SK, :sk)',
                FilterExpression: 'rotated = :false',
                ExpressionAttributeValues: {
                    ':pk': `USER#${userId}`,
                    ':sk': 'REFRESH#',
                    ':false': false,
                },
                ExclusiveStartKey: lastEvaluatedKey,
            })
        );

        if (result.Items && result.Items.length > 0) {
            const now = new Date().toISOString();

            // Revoke each token
            for (const item of result.Items) {
                try {
                    await client.send(
                        new UpdateCommand({
                            TableName: tableName,
                            Key: {
                                PK: item.PK,
                                SK: item.SK,
                            },
                            UpdateExpression:
                                'SET rotated = :true, rotatedAt = :now, revokedAt = :now, revokedReason = :reason, updatedAt = :now',
                            ConditionExpression: 'rotated = :false',
                            ExpressionAttributeValues: {
                                ':true': true,
                                ':false': false,
                                ':now': now,
                                ':reason': 'user_deactivated_scim',
                            },
                        })
                    );
                    revokedCount++;
                } catch (err) {
                    // Ignore ConditionalCheckFailedException (already rotated)
                    if ((err as Error).name !== 'ConditionalCheckFailedException') {
                        log.warn('Failed to revoke token', { pk: item.PK, error: (err as Error).message });
                    }
                }
            }
        }

        lastEvaluatedKey = result.LastEvaluatedKey;
    } while (lastEvaluatedKey);

    return revokedCount;
}

// =============================================================================
// PATCH User Handler
// =============================================================================

/**
 * Handle PATCH /scim/v2/Users/{id} - Update a user.
 *
 * @param userId - User ID from path parameter
 * @param body - Parsed SCIM PATCH request
 * @param config - Environment configuration
 * @param client - DynamoDB document client
 * @param audit - Audit logger
 * @param requestId - Request ID for logging
 * @returns SCIM response (200 OK or error)
 */
export async function handlePatchUser(
    userId: string,
    body: ScimPatchRequest,
    config: EnvConfig,
    client: DynamoDBDocumentClient,
    audit: AuditLogger,
    requestId: string
): Promise<APIGatewayProxyResultV2> {
    const log = new Logger(requestId);

    // Step 1: Validate request
    const validation = validatePatchRequest(body);
    if (!validation.valid) {
        return scimBadRequest(validation.error || 'Invalid request', 'invalidSyntax');
    }

    // Step 2: Fetch existing user
    const userResult = await client.send(
        new GetCommand({
            TableName: config.tableName,
            Key: { PK: `USER#${userId}`, SK: 'PROFILE' },
        })
    );

    if (!userResult.Item) {
        return scimNotFound(`User ${userId} not found`);
    }

    const user = userResult.Item as UserItem;
    let userUpdated = false;
    let newActiveStatus: boolean | undefined;

    // Step 3: Process operations
    for (const op of body.Operations) {
        const opType = op.op.toLowerCase();
        const path = op.path?.toLowerCase();

        // Currently only support replace on active attribute
        if (opType === 'replace') {
            if (path === 'active' || (!path && typeof op.value === 'object' && 'active' in (op.value as object))) {
                // Extract active value
                let activeValue: boolean;
                if (path === 'active') {
                    activeValue = op.value === true || op.value === 'true';
                } else {
                    activeValue = (op.value as { active: boolean }).active === true;
                }

                newActiveStatus = activeValue;
                userUpdated = true;
            } else if (!path && typeof op.value === 'object') {
                // Handle replace without path (full object replacement)
                const valueObj = op.value as Record<string, unknown>;
                if ('active' in valueObj) {
                    newActiveStatus = valueObj.active === true;
                    userUpdated = true;
                }
            } else {
                // Unsupported path for replace
                return scimBadRequest(`Unsupported path for replace: ${op.path}`, 'invalidPath');
            }
        } else if (opType === 'add' || opType === 'remove') {
            // Currently not supporting add/remove operations
            return scimBadRequest(`Operation ${opType} is not supported for User resource`, 'invalidValue');
        }
    }

    // Step 4: Apply updates if any
    if (userUpdated && newActiveStatus !== undefined) {
        const wasActive = user.status === 'ACTIVE';
        const willBeActive = newActiveStatus;

        // Update user status
        const updateParams = buildStatusUpdateParams(newActiveStatus);

        try {
            await client.send(
                new UpdateCommand({
                    TableName: config.tableName,
                    Key: { PK: `USER#${userId}`, SK: 'PROFILE' },
                    UpdateExpression: updateParams.updateExpression,
                    ExpressionAttributeNames: updateParams.expressionAttributeNames,
                    ExpressionAttributeValues: updateParams.expressionAttributeValues,
                    ConditionExpression: 'attribute_exists(PK)',
                })
            );
        } catch (err) {
            if ((err as Error).name === 'ConditionalCheckFailedException') {
                return scimNotFound(`User ${userId} not found`);
            }
            throw err;
        }

        // Update local user object for response
        user.status = newActiveStatus ? 'ACTIVE' : 'SUSPENDED';
        user.updatedAt = new Date().toISOString();

        // Security Hook: Revoke all tokens when user is deactivated
        if (wasActive && !willBeActive) {
            log.info('User deactivated, revoking refresh tokens', { userId });

            const revokedCount = await revokeUserRefreshTokens(client, config.tableName, userId, log);

            log.info('Refresh tokens revoked', { userId, count: revokedCount });

            audit.log({
                action: 'TOKEN_REVOKED',
                actor: { type: 'SYSTEM' },
                details: {
                    tokenType: 'refresh_token',
                    reason: 'user_logout' as const,
                    sub: userId,
                    tokensRevoked: revokedCount,
                },
            });
        }

        // Audit log status change
        audit.log({
            action: newActiveStatus ? 'USER_UPDATED' : 'USER_DEACTIVATED',
            actor: { type: 'SYSTEM' },
            details: {
                sub: userId,
                email: user.email,
                previousStatus: wasActive ? 'ACTIVE' : 'SUSPENDED',
                newStatus: newActiveStatus ? 'ACTIVE' : 'SUSPENDED',
            },
        });
    }

    // Step 5: Return updated user
    const scimUser = userItemToScimUser(user, config);
    return scimUserResponse(scimUser, 200);
}
