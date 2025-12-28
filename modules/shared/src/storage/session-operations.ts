/**
 * OAuth Server - Login Session Storage Operations
 *
 * DynamoDB operations for login session entities.
 * Sessions are temporary and used during the authorization flow.
 *
 * Key Pattern:
 *   PK: SESSION#<session_id>
 *   SK: METADATA
 *   GSI1PK: CLIENT#<client_id>
 *   GSI1SK: SESSION#<timestamp>
 *
 * Lifecycle:
 *   1. Created by /authorize with OAuth parameters and PKCE challenge
 *   2. Updated by auth strategy with authenticatedUserId after login
 *   3. Consumed by /authorize/callback to generate authorization code
 *   4. Deleted after code generation (single-use)
 *
 * @module storage/session-operations
 */

import {
    DynamoDBDocumentClient,
    GetCommand,
    PutCommand,
    UpdateCommand,
    DeleteCommand,
    QueryCommand,
    BatchWriteCommand,
} from '@aws-sdk/lib-dynamodb';
import type { LoginSessionItem } from '../../../shared_types/schema';
import { withRetry } from './retry';

/**
 * Retrieve a login session by its ID.
 *
 * @param client - DynamoDB Document client
 * @param tableName - DynamoDB table name
 * @param sessionId - The session identifier
 * @returns LoginSessionItem or null if not found
 */
export async function getLoginSession(
    client: DynamoDBDocumentClient,
    tableName: string,
    sessionId: string
): Promise<LoginSessionItem | null> {
    const result = await withRetry(async () => {
        return client.send(
            new GetCommand({
                TableName: tableName,
                Key: {
                    PK: `SESSION#${sessionId}`,
                    SK: 'METADATA',
                },
            })
        );
    });

    if (!result.Item) {
        return null;
    }

    return result.Item as LoginSessionItem;
}

/**
 * Save a new login session.
 *
 * @param client - DynamoDB Document client
 * @param tableName - DynamoDB table name
 * @param session - The LoginSessionItem to save
 */
export async function saveLoginSession(
    client: DynamoDBDocumentClient,
    tableName: string,
    session: LoginSessionItem
): Promise<void> {
    const now = new Date().toISOString();

    await withRetry(async () => {
        return client.send(
            new PutCommand({
                TableName: tableName,
                Item: {
                    ...session,
                    PK: `SESSION#${session.sessionId}`,
                    SK: 'METADATA',
                    GSI1PK: `CLIENT#${session.clientId}`,
                    GSI1SK: `SESSION#${now}`,
                    entityType: 'LOGIN_SESSION',
                    updatedAt: now,
                    createdAt: session.createdAt || now,
                },
            })
        );
    });
}

/**
 * Update a login session with authentication result.
 *
 * Called by authentication strategies after successful user authentication
 * to record the authenticated user ID and authentication method.
 *
 * @param client - DynamoDB Document client
 * @param tableName - DynamoDB table name
 * @param sessionId - The session identifier
 * @param authenticatedUserId - The authenticated user's subject identifier
 * @param authMethod - The authentication method used (e.g., 'password', 'saml')
 * @returns true if successfully updated, false if session not found or expired
 */
export async function updateLoginSessionAuth(
    client: DynamoDBDocumentClient,
    tableName: string,
    sessionId: string,
    authenticatedUserId: string,
    authMethod: string
): Promise<boolean> {
    try {
        const now = new Date().toISOString();

        await withRetry(async () => {
            return client.send(
                new UpdateCommand({
                    TableName: tableName,
                    Key: {
                        PK: `SESSION#${sessionId}`,
                        SK: 'METADATA',
                    },
                    UpdateExpression:
                        'SET authenticatedUserId = :userId, authenticatedAt = :authAt, authMethod = :method, updatedAt = :now',
                    ConditionExpression: 'attribute_exists(PK) AND attribute_not_exists(authenticatedUserId)',
                    ExpressionAttributeValues: {
                        ':userId': authenticatedUserId,
                        ':authAt': now,
                        ':method': authMethod,
                        ':now': now,
                    },
                })
            );
        });
        return true;
    } catch (error) {
        if ((error as Error).name === 'ConditionalCheckFailedException') {
            return false;
        }
        throw error;
    }
}

/**
 * Delete a login session after it's been used.
 *
 * @param client - DynamoDB Document client
 * @param tableName - DynamoDB table name
 * @param sessionId - The session identifier
 */
export async function deleteLoginSession(
    client: DynamoDBDocumentClient,
    tableName: string,
    sessionId: string
): Promise<void> {
    await withRetry(async () => {
        return client.send(
            new DeleteCommand({
                TableName: tableName,
                Key: {
                    PK: `SESSION#${sessionId}`,
                    SK: 'METADATA',
                },
            })
        );
    });
}

/**
 * Delete expired login sessions for a specific client.
 *
 * Sessions have TTL for automatic cleanup, but this method
 * can be used for immediate cleanup when needed.
 *
 * Note: DynamoDB TTL handles automatic cleanup of expired items within 48 hours.
 * This method is for explicit cleanup scenarios where immediate removal is required.
 *
 * @param client - DynamoDB Document client
 * @param tableName - DynamoDB table name
 * @param clientId - Client ID to scope cleanup
 * @returns Number of sessions deleted
 */
export async function cleanupExpiredSessions(
    client: DynamoDBDocumentClient,
    tableName: string,
    clientId: string
): Promise<number> {
    const now = Math.floor(Date.now() / 1000);
    let deletedCount = 0;
    let lastEvaluatedKey: Record<string, unknown> | undefined;

    do {
        const result = await withRetry(async () => {
            return client.send(
                new QueryCommand({
                    TableName: tableName,
                    IndexName: 'GSI1',
                    KeyConditionExpression: 'GSI1PK = :pk AND begins_with(GSI1SK, :sk)',
                    FilterExpression: 'ttl < :now',
                    ExpressionAttributeValues: {
                        ':pk': `CLIENT#${clientId}`,
                        ':sk': 'SESSION#',
                        ':now': now,
                    },
                    ExclusiveStartKey: lastEvaluatedKey,
                })
            );
        });

        if (result.Items && result.Items.length > 0) {
            // Batch delete in groups of 25 (DynamoDB BatchWriteItem limit)
            const batches: Record<string, unknown>[][] = [];
            for (let i = 0; i < result.Items.length; i += 25) {
                batches.push(result.Items.slice(i, i + 25));
            }

            for (const batch of batches) {
                const response = await withRetry(async () => {
                    return client.send(
                        new BatchWriteCommand({
                            RequestItems: {
                                [tableName]: batch.map(item => ({
                                    DeleteRequest: {
                                        Key: { PK: item.PK, SK: item.SK },
                                    },
                                })),
                            },
                        })
                    );
                });

                // Calculate successful deletes (batch size minus unprocessed items)
                const unprocessedCount = response.UnprocessedItems?.[tableName]?.length ?? 0;
                deletedCount += batch.length - unprocessedCount;
            }
        }

        lastEvaluatedKey = result.LastEvaluatedKey;
    } while (lastEvaluatedKey);

    return deletedCount;
}
