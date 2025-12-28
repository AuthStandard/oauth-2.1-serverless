/**
 * OAuth Server - Refresh Token Storage Operations
 *
 * DynamoDB operations for refresh token entities.
 * Implements token rotation with conditional updates and retry logic.
 *
 * Key Pattern:
 *   PK: REFRESH#<token_hash>
 *   SK: METADATA
 *   GSI1PK: USER#<sub>
 *   GSI1SK: REFRESH#<timestamp>
 *   GSI2PK: FAMILY#<family_id>
 *   GSI2SK: REFRESH#<timestamp>
 *
 * Security:
 *   - Tokens are stored as SHA-256 hashes (never plaintext)
 *   - Token rotation creates audit trail via replacedByHash
 *   - Conditional updates prevent race conditions
 *   - GSI2 enables efficient token family revocation
 *
 * @module storage/refresh-token-operations
 */

import {
    DynamoDBDocumentClient,
    GetCommand,
    PutCommand,
    UpdateCommand,
    QueryCommand,
} from '@aws-sdk/lib-dynamodb';
import type { RefreshTokenItem } from '../../../shared_types/schema';
import { withRetry } from './retry';

/**
 * Retrieve a refresh token by its hash.
 *
 * @param client - DynamoDB Document client
 * @param tableName - DynamoDB table name
 * @param tokenHash - SHA256 hash of the refresh token
 * @returns RefreshTokenItem or null if not found
 */
export async function getRefreshToken(
    client: DynamoDBDocumentClient,
    tableName: string,
    tokenHash: string
): Promise<RefreshTokenItem | null> {
    const result = await withRetry(async () => {
        return client.send(
            new GetCommand({
                TableName: tableName,
                Key: {
                    PK: `REFRESH#${tokenHash}`,
                    SK: 'METADATA',
                },
            })
        );
    });

    if (!result.Item) {
        return null;
    }

    return result.Item as RefreshTokenItem;
}

/**
 * Save a new refresh token.
 *
 * Refresh tokens are stored with their SHA-256 hash as the key.
 * The `rotated` flag is initialized to false and set to true when
 * the token is used and a new token is issued (token rotation).
 *
 * GSI2 is populated with the token family ID to enable efficient
 * family-wide revocation without table scans.
 *
 * @param client - DynamoDB Document client
 * @param tableName - DynamoDB table name
 * @param token - The RefreshTokenItem to save (must include ttl for automatic expiration)
 *
 * @see OAuth 2.1 Section 4.3.3 - Refresh token rotation is RECOMMENDED
 */
export async function saveRefreshToken(
    client: DynamoDBDocumentClient,
    tableName: string,
    token: RefreshTokenItem
): Promise<void> {
    const now = new Date().toISOString();

    await withRetry(async () => {
        return client.send(
            new PutCommand({
                TableName: tableName,
                Item: {
                    ...token,
                    PK: `REFRESH#${token.tokenHash}`,
                    SK: 'METADATA',
                    GSI1PK: `USER#${token.sub}`,
                    GSI1SK: `REFRESH#${now}`,
                    GSI2PK: `FAMILY#${token.familyId}`,
                    GSI2SK: `REFRESH#${now}`,
                    entityType: 'REFRESH_TOKEN',
                    rotated: token.rotated ?? false,
                    updatedAt: now,
                    createdAt: token.createdAt || now,
                },
            })
        );
    });
}

/**
 * Mark a refresh token as rotated.
 *
 * Per OAuth 2.1 Section 4.3.3, refresh token rotation is RECOMMENDED.
 * When a refresh token is used, a new refresh token SHOULD be issued
 * and the old one invalidated.
 *
 * @param client - DynamoDB Document client
 * @param tableName - DynamoDB table name
 * @param tokenHash - Hash of the token being rotated
 * @param replacedByHash - Hash of the new token
 * @returns true if successfully rotated, false if already rotated or not found
 */
export async function rotateRefreshToken(
    client: DynamoDBDocumentClient,
    tableName: string,
    tokenHash: string,
    replacedByHash: string
): Promise<boolean> {
    try {
        const now = new Date().toISOString();

        await withRetry(async () => {
            return client.send(
                new UpdateCommand({
                    TableName: tableName,
                    Key: {
                        PK: `REFRESH#${tokenHash}`,
                        SK: 'METADATA',
                    },
                    UpdateExpression:
                        'SET rotated = :true, rotatedAt = :now, replacedByHash = :newHash, updatedAt = :now',
                    ConditionExpression: 'attribute_exists(PK) AND rotated = :false',
                    ExpressionAttributeValues: {
                        ':true': true,
                        ':false': false,
                        ':now': now,
                        ':newHash': replacedByHash,
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
 * Revoke all refresh tokens for a user.
 *
 * Used for security events such as:
 * - User logout (revoke all sessions)
 * - Admin action (force logout)
 * - Security incident (compromised account)
 *
 * @param client - DynamoDB Document client
 * @param tableName - DynamoDB table name
 * @param userId - The user's subject identifier
 * @param reason - Reason for revocation (for audit trail)
 * @returns Number of tokens revoked
 */
export async function revokeAllUserRefreshTokens(
    client: DynamoDBDocumentClient,
    tableName: string,
    userId: string,
    reason: 'user_logout' | 'admin_action' | 'security_event'
): Promise<number> {
    const now = new Date().toISOString();
    let revokedCount = 0;
    let lastEvaluatedKey: Record<string, unknown> | undefined;

    do {
        const result = await withRetry(async () => {
            return client.send(
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
        });

        if (result.Items && result.Items.length > 0) {
            for (const item of result.Items) {
                try {
                    await withRetry(async () => {
                        return client.send(
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
                                    ':reason': reason,
                                },
                            })
                        );
                    });
                    revokedCount++;
                } catch (error) {
                    // Ignore ConditionalCheckFailedException (already rotated)
                    if ((error as Error).name !== 'ConditionalCheckFailedException') {
                        throw error;
                    }
                }
            }
        }

        lastEvaluatedKey = result.LastEvaluatedKey;
    } while (lastEvaluatedKey);

    return revokedCount;
}

/**
 * Revoke all tokens in a token family.
 *
 * Per OAuth 2.1 Section 4.3.3, if a refresh token is used more than once,
 * the authorization server SHOULD revoke all tokens in the family.
 * This prevents refresh token replay attacks.
 *
 * Uses GSI2 (FAMILY#<family_id>) for efficient queries instead of table scans.
 * This enables O(n) performance where n is the family size, not table size.
 *
 * @param client - DynamoDB Document client
 * @param tableName - DynamoDB table name
 * @param familyId - The token family identifier
 * @returns Number of tokens revoked
 *
 * @see OAuth 2.1 Draft Section 4.3.3 - Refresh Token Rotation
 */
export async function revokeTokenFamily(
    client: DynamoDBDocumentClient,
    tableName: string,
    familyId: string
): Promise<number> {
    const now = new Date().toISOString();
    let revokedCount = 0;
    let lastEvaluatedKey: Record<string, unknown> | undefined;

    // Use GSI2 for efficient family lookup instead of table scan
    do {
        const result = await withRetry(async () => {
            return client.send(
                new QueryCommand({
                    TableName: tableName,
                    IndexName: 'GSI2',
                    KeyConditionExpression: 'GSI2PK = :pk',
                    FilterExpression: 'rotated = :false',
                    ExpressionAttributeValues: {
                        ':pk': `FAMILY#${familyId}`,
                        ':false': false,
                    },
                    ExclusiveStartKey: lastEvaluatedKey,
                })
            );
        });

        if (result.Items && result.Items.length > 0) {
            for (const item of result.Items) {
                try {
                    await withRetry(async () => {
                        return client.send(
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
                                    ':reason': 'token_reuse_detected',
                                },
                            })
                        );
                    });
                    revokedCount++;
                } catch (error) {
                    if ((error as Error).name !== 'ConditionalCheckFailedException') {
                        throw error;
                    }
                }
            }
        }

        lastEvaluatedKey = result.LastEvaluatedKey;
    } while (lastEvaluatedKey);

    return revokedCount;
}
