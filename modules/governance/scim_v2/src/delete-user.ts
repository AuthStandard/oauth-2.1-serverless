/**
 * SCIM v2 User Provisioning - Delete User Handler
 *
 * Implements DELETE /scim/v2/Users/{id} per RFC 7644 Section 3.6.
 * Permanently removes a user from the system with full cleanup.
 *
 * Security:
 * - Requires valid JWT with scim:users scope
 * - Revokes all active tokens for the user
 * - Deletes all sessions
 * - SOC2-compliant audit logging
 *
 * @module governance/scim_v2/delete-user
 * @see RFC 7644 Section 3.6 - Deleting Resources
 */

import type { APIGatewayProxyResultV2 } from 'aws-lambda';
import type { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { GetCommand, DeleteCommand, QueryCommand, BatchWriteCommand } from '@aws-sdk/lib-dynamodb';
import type { EnvConfig } from './types';
import { scimNotFound, scimNoContent } from './responses';

// =============================================================================
// Types
// =============================================================================

interface AuditLogger {
    log(entry: {
        action: string;
        actor: { type: string; sub?: string };
        target?: { type: string; id: string };
        details?: Record<string, unknown>;
    }): void;
}

interface UserItem {
    PK: string;
    SK: string;
    sub: string;
    email: string;
    status: string;
}

// =============================================================================
// Token and Session Cleanup
// =============================================================================

/**
 * Revoke all refresh tokens for a user.
 * Queries GSI1 for all tokens belonging to the user and marks them as revoked.
 */
async function revokeUserTokens(
    sub: string,
    client: DynamoDBDocumentClient,
    tableName: string
): Promise<number> {
    let revokedCount = 0;
    let lastEvaluatedKey: Record<string, unknown> | undefined;

    do {
        const result = await client.send(
            new QueryCommand({
                TableName: tableName,
                IndexName: 'GSI1',
                KeyConditionExpression: 'GSI1PK = :pk AND begins_with(GSI1SK, :sk)',
                ExpressionAttributeValues: {
                    ':pk': `USER#${sub}`,
                    ':sk': 'REFRESH#',
                },
                ExclusiveStartKey: lastEvaluatedKey,
            })
        );

        if (result.Items && result.Items.length > 0) {
            // Process in batches of 25 (DynamoDB BatchWrite limit)
            for (let i = 0; i < result.Items.length; i += 25) {
                const batch = result.Items.slice(i, i + 25);
                const deleteRequests = batch.map(item => ({
                    DeleteRequest: {
                        Key: { PK: item.PK, SK: 'METADATA' },
                    },
                }));

                await client.send(
                    new BatchWriteCommand({
                        RequestItems: {
                            [tableName]: deleteRequests,
                        },
                    })
                );
                revokedCount += batch.length;
            }
        }

        lastEvaluatedKey = result.LastEvaluatedKey;
    } while (lastEvaluatedKey);

    return revokedCount;
}

/**
 * Delete all sessions for a user.
 */
async function deleteUserSessions(
    sub: string,
    client: DynamoDBDocumentClient,
    tableName: string
): Promise<number> {
    let deletedCount = 0;
    let lastEvaluatedKey: Record<string, unknown> | undefined;

    do {
        const result = await client.send(
            new QueryCommand({
                TableName: tableName,
                IndexName: 'GSI1',
                KeyConditionExpression: 'GSI1PK = :pk AND begins_with(GSI1SK, :sk)',
                ExpressionAttributeValues: {
                    ':pk': `USER#${sub}`,
                    ':sk': 'SESSION#',
                },
                ExclusiveStartKey: lastEvaluatedKey,
            })
        );

        if (result.Items && result.Items.length > 0) {
            // Process in batches of 25
            for (let i = 0; i < result.Items.length; i += 25) {
                const batch = result.Items.slice(i, i + 25);
                const deleteRequests = batch.map(item => ({
                    DeleteRequest: {
                        Key: { PK: item.PK, SK: item.SK || 'METADATA' },
                    },
                }));

                await client.send(
                    new BatchWriteCommand({
                        RequestItems: {
                            [tableName]: deleteRequests,
                        },
                    })
                );
                deletedCount += batch.length;
            }
        }

        lastEvaluatedKey = result.LastEvaluatedKey;
    } while (lastEvaluatedKey);

    return deletedCount;
}

/**
 * Delete user's authorization codes.
 */
async function deleteUserAuthCodes(
    sub: string,
    client: DynamoDBDocumentClient,
    tableName: string
): Promise<number> {
    let deletedCount = 0;
    let lastEvaluatedKey: Record<string, unknown> | undefined;

    do {
        const result = await client.send(
            new QueryCommand({
                TableName: tableName,
                IndexName: 'GSI1',
                KeyConditionExpression: 'GSI1PK = :pk AND begins_with(GSI1SK, :sk)',
                ExpressionAttributeValues: {
                    ':pk': `USER#${sub}`,
                    ':sk': 'CODE#',
                },
                ExclusiveStartKey: lastEvaluatedKey,
            })
        );

        if (result.Items && result.Items.length > 0) {
            for (let i = 0; i < result.Items.length; i += 25) {
                const batch = result.Items.slice(i, i + 25);
                const deleteRequests = batch.map(item => ({
                    DeleteRequest: {
                        Key: { PK: item.PK, SK: item.SK || 'METADATA' },
                    },
                }));

                await client.send(
                    new BatchWriteCommand({
                        RequestItems: {
                            [tableName]: deleteRequests,
                        },
                    })
                );
                deletedCount += batch.length;
            }
        }

        lastEvaluatedKey = result.LastEvaluatedKey;
    } while (lastEvaluatedKey);

    return deletedCount;
}

// =============================================================================
// Handler
// =============================================================================

/**
 * Handle DELETE /scim/v2/Users/{id} request.
 *
 * Per RFC 7644 Section 3.6:
 * - Returns 204 No Content on success
 * - Returns 404 Not Found if user doesn't exist
 *
 * Cleanup performed:
 * 1. Revoke all refresh tokens
 * 2. Delete all sessions
 * 3. Delete all authorization codes
 * 4. Delete user profile record
 *
 * @param userId - User ID from path parameter
 * @param config - Environment configuration
 * @param client - DynamoDB document client
 * @param audit - Audit logger
 * @param requestId - AWS request ID for tracing
 * @param actorSub - Subject identifier of the authenticated admin performing the deletion
 * @returns SCIM response
 */
export async function handleDeleteUser(
    userId: string,
    config: EnvConfig,
    client: DynamoDBDocumentClient,
    audit: AuditLogger,
    requestId: string,
    actorSub?: string
): Promise<APIGatewayProxyResultV2> {
    // Fetch existing user
    const existingResult = await client.send(
        new GetCommand({
            TableName: config.tableName,
            Key: { PK: `USER#${userId}`, SK: 'PROFILE' },
        })
    );

    if (!existingResult.Item) {
        return scimNotFound('User', userId);
    }

    const user = existingResult.Item as UserItem;

    // Perform cleanup in parallel for efficiency
    const [tokensRevoked, sessionsDeleted, codesDeleted] = await Promise.all([
        revokeUserTokens(userId, client, config.tableName),
        deleteUserSessions(userId, client, config.tableName),
        deleteUserAuthCodes(userId, client, config.tableName),
    ]);

    // Delete the user profile record
    await client.send(
        new DeleteCommand({
            TableName: config.tableName,
            Key: { PK: `USER#${userId}`, SK: 'PROFILE' },
        })
    );

    // Delete email index entry if exists
    if (user.email) {
        try {
            await client.send(
                new DeleteCommand({
                    TableName: config.tableName,
                    Key: { PK: `EMAIL#${user.email.toLowerCase()}`, SK: 'USER' },
                })
            );
        } catch {
            // Ignore errors - email index may not exist
        }
    }

    // Audit log the deletion with proper actor attribution
    audit.log({
        action: 'USER_DELETED',
        actor: actorSub ? { type: 'USER', sub: actorSub } : { type: 'SYSTEM' },
        target: { type: 'USER', id: userId },
        details: {
            email: user.email,
            previousStatus: user.status,
            tokensRevoked,
            sessionsDeleted,
            codesDeleted,
            requestId,
        },
    });

    // Return 204 No Content per RFC 7644 Section 3.6
    return scimNoContent();
}
