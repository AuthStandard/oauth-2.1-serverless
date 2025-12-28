/**
 * OAuth Server - Password Strategy Database Operations
 *
 * DynamoDB operations for the password authentication flow.
 * Implements Single Table Design patterns.
 */

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
    DynamoDBDocumentClient,
    GetCommand,
    UpdateCommand,
    QueryCommand,
    PutCommand,
    DeleteCommand,
} from '@aws-sdk/lib-dynamodb';
import type { LoginSessionItem, UserItem, PasswordResetTokenItem } from './types';

// =============================================================================
// DynamoDB Client Singleton
// =============================================================================

let docClient: DynamoDBDocumentClient | null = null;

/**
 * Get the DynamoDB Document Client singleton.
 * Reuses the client across Lambda invocations for connection pooling.
 */
export function getDocClient(): DynamoDBDocumentClient {
    if (!docClient) {
        const client = new DynamoDBClient({});
        docClient = DynamoDBDocumentClient.from(client, {
            marshallOptions: { removeUndefinedValues: true },
        });
    }
    return docClient;
}

// =============================================================================
// Session Operations
// =============================================================================

/**
 * Fetch a login session by its ID.
 * Returns null if the session doesn't exist.
 */
export async function getSession(
    tableName: string,
    sessionId: string
): Promise<LoginSessionItem | null> {
    const client = getDocClient();
    const result = await client.send(
        new GetCommand({
            TableName: tableName,
            Key: { PK: `SESSION#${sessionId}`, SK: 'METADATA' },
        })
    );
    return (result.Item as LoginSessionItem) || null;
}

/**
 * Update a session with the authenticated user ID and authentication method.
 * Uses a condition expression to prevent race conditions and replay attacks.
 *
 * Conditions enforced atomically:
 * - Session must exist
 * - Session must not already be authenticated (prevents replay)
 * - Session TTL must not have expired (defense-in-depth)
 *
 * @param tableName - DynamoDB table name
 * @param sessionId - The session identifier
 * @param userId - The authenticated user's subject identifier
 * @param pendingMfa - If true, marks session as pending MFA verification
 * @returns true if successfully updated, false if session not found, expired, or already authenticated
 */
export async function updateSessionWithUser(
    tableName: string,
    sessionId: string,
    userId: string,
    pendingMfa: boolean = false
): Promise<boolean> {
    const client = getDocClient();
    const now = new Date().toISOString();
    const nowEpochSeconds = Math.floor(Date.now() / 1000);

    try {
        if (pendingMfa) {
            // MFA pending - set user but mark as not fully authenticated
            await client.send(
                new UpdateCommand({
                    TableName: tableName,
                    Key: { PK: `SESSION#${sessionId}`, SK: 'METADATA' },
                    UpdateExpression: 'SET pendingMfaUserId = :userId, authMethod = :method, updatedAt = :now',
                    ConditionExpression: 'attribute_exists(PK) AND attribute_not_exists(authenticatedUserId) AND attribute_not_exists(pendingMfaUserId) AND (attribute_not_exists(#ttl) OR #ttl > :nowEpoch)',
                    ExpressionAttributeNames: {
                        '#ttl': 'ttl',
                    },
                    ExpressionAttributeValues: {
                        ':userId': userId,
                        ':method': 'password',
                        ':now': now,
                        ':nowEpoch': nowEpochSeconds,
                    },
                })
            );
        } else {
            // Full authentication - set authenticatedUserId
            await client.send(
                new UpdateCommand({
                    TableName: tableName,
                    Key: { PK: `SESSION#${sessionId}`, SK: 'METADATA' },
                    UpdateExpression: 'SET authenticatedUserId = :userId, authenticatedAt = :authAt, authMethod = :method, updatedAt = :now REMOVE pendingMfaUserId',
                    ConditionExpression: 'attribute_exists(PK) AND attribute_not_exists(authenticatedUserId) AND (attribute_not_exists(#ttl) OR #ttl > :nowEpoch)',
                    ExpressionAttributeNames: {
                        '#ttl': 'ttl',
                    },
                    ExpressionAttributeValues: {
                        ':userId': userId,
                        ':authAt': now,
                        ':method': 'password',
                        ':now': now,
                        ':nowEpoch': nowEpochSeconds,
                    },
                })
            );
        }
        return true;
    } catch (err) {
        const error = err as Error;
        if (error.name === 'ConditionalCheckFailedException') {
            return false;
        }
        throw err;
    }
}

// =============================================================================
// User Operations
// =============================================================================

/**
 * Fetch a user by email address using GSI1.
 * Returns null if the user doesn't exist.
 */
export async function getUserByEmail(
    tableName: string,
    email: string
): Promise<UserItem | null> {
    const client = getDocClient();
    const result = await client.send(
        new QueryCommand({
            TableName: tableName,
            IndexName: 'GSI1',
            KeyConditionExpression: 'GSI1PK = :pk AND GSI1SK = :sk',
            ExpressionAttributeValues: {
                ':pk': `EMAIL#${email.toLowerCase()}`,
                ':sk': 'USER',
            },
            Limit: 1,
        })
    );

    if (!result.Items || result.Items.length === 0) {
        return null;
    }

    return result.Items[0] as UserItem;
}

/**
 * Increment the failed login attempt counter for a user.
 * Returns the updated count.
 */
export async function incrementFailedAttempts(
    tableName: string,
    userId: string
): Promise<number> {
    const client = getDocClient();
    const now = new Date().toISOString();

    const result = await client.send(
        new UpdateCommand({
            TableName: tableName,
            Key: { PK: `USER#${userId}`, SK: 'PROFILE' },
            UpdateExpression: 'SET failedLoginAttempts = if_not_exists(failedLoginAttempts, :zero) + :one, lastFailedLoginAt = :now, updatedAt = :now',
            ExpressionAttributeValues: {
                ':zero': 0,
                ':one': 1,
                ':now': now,
            },
            ReturnValues: 'UPDATED_NEW',
        })
    );

    return (result.Attributes?.failedLoginAttempts as number) || 1;
}

/**
 * Reset the failed login attempt counter after successful login.
 */
export async function resetFailedAttempts(
    tableName: string,
    userId: string
): Promise<void> {
    const client = getDocClient();
    const now = new Date().toISOString();

    await client.send(
        new UpdateCommand({
            TableName: tableName,
            Key: { PK: `USER#${userId}`, SK: 'PROFILE' },
            UpdateExpression: 'SET failedLoginAttempts = :zero, updatedAt = :now REMOVE lockedUntil',
            ExpressionAttributeValues: {
                ':zero': 0,
                ':now': now,
            },
        })
    );
}

/**
 * Lock a user account until the specified time.
 */
export async function lockUserAccount(
    tableName: string,
    userId: string,
    lockedUntil: string
): Promise<void> {
    const client = getDocClient();
    const now = new Date().toISOString();

    await client.send(
        new UpdateCommand({
            TableName: tableName,
            Key: { PK: `USER#${userId}`, SK: 'PROFILE' },
            UpdateExpression: 'SET lockedUntil = :lockedUntil, updatedAt = :now',
            ExpressionAttributeValues: {
                ':lockedUntil': lockedUntil,
                ':now': now,
            },
        })
    );
}


// =============================================================================
// Password Reset Token Operations
// =============================================================================

/**
 * Save a password reset token to DynamoDB.
 * Token is stored as a SHA-256 hash for security.
 */
export async function savePasswordResetToken(
    tableName: string,
    params: {
        tokenHash: string;
        userId: string;
        email: string;
        ttl: number;
    }
): Promise<void> {
    const client = getDocClient();
    const now = new Date().toISOString();

    const item: PasswordResetTokenItem = {
        PK: `RESET#${params.tokenHash}`,
        SK: 'METADATA',
        entityType: 'PASSWORD_RESET_TOKEN',
        tokenHash: params.tokenHash,
        userId: params.userId,
        email: params.email,
        createdAt: now,
        ttl: params.ttl,
    };

    await client.send(
        new PutCommand({
            TableName: tableName,
            Item: item,
        })
    );
}

/**
 * Fetch a password reset token by its hash.
 * Returns null if the token doesn't exist or has expired.
 */
export async function getPasswordResetToken(
    tableName: string,
    tokenHash: string
): Promise<PasswordResetTokenItem | null> {
    const client = getDocClient();
    const result = await client.send(
        new GetCommand({
            TableName: tableName,
            Key: { PK: `RESET#${tokenHash}`, SK: 'METADATA' },
        })
    );
    return (result.Item as PasswordResetTokenItem) || null;
}

/**
 * Delete a password reset token after use.
 * Tokens are single-use for security.
 */
export async function deletePasswordResetToken(
    tableName: string,
    tokenHash: string
): Promise<void> {
    const client = getDocClient();
    await client.send(
        new DeleteCommand({
            TableName: tableName,
            Key: { PK: `RESET#${tokenHash}`, SK: 'METADATA' },
        })
    );
}

/**
 * Update a user's password hash.
 * Also clears any account lockout.
 */
export async function updateUserPassword(
    tableName: string,
    userId: string,
    passwordHash: string
): Promise<boolean> {
    const client = getDocClient();
    const now = new Date().toISOString();

    try {
        await client.send(
            new UpdateCommand({
                TableName: tableName,
                Key: { PK: `USER#${userId}`, SK: 'PROFILE' },
                UpdateExpression: 'SET passwordHash = :hash, failedLoginAttempts = :zero, updatedAt = :now REMOVE lockedUntil',
                ConditionExpression: 'attribute_exists(PK)',
                ExpressionAttributeValues: {
                    ':hash': passwordHash,
                    ':zero': 0,
                    ':now': now,
                },
            })
        );
        return true;
    } catch (err) {
        const error = err as Error;
        if (error.name === 'ConditionalCheckFailedException') {
            return false;
        }
        throw err;
    }
}
