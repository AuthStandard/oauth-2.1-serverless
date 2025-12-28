/**
 * OAuth Server - User Storage Operations
 *
 * DynamoDB operations for user entities.
 *
 * Key Pattern:
 *   PK: USER#<sub_id>
 *   SK: PROFILE
 *   GSI1PK: EMAIL#<email>
 *   GSI1SK: USER
 *
 * @module storage/user-operations
 */

import { DynamoDBDocumentClient, GetCommand, PutCommand, QueryCommand } from '@aws-sdk/lib-dynamodb';
import type { UserItem } from '../../../shared_types/schema';
import { withRetry } from './retry';

/**
 * Retrieve a user by their subject identifier (sub).
 *
 * @param client - DynamoDB Document client
 * @param tableName - DynamoDB table name
 * @param userId - The user's sub (UUID)
 * @returns UserItem or null if not found
 */
export async function getUser(
    client: DynamoDBDocumentClient,
    tableName: string,
    userId: string
): Promise<UserItem | null> {
    const result = await withRetry(async () => {
        return client.send(
            new GetCommand({
                TableName: tableName,
                Key: {
                    PK: `USER#${userId}`,
                    SK: 'PROFILE',
                },
            })
        );
    });

    if (!result.Item) {
        return null;
    }

    return result.Item as UserItem;
}

/**
 * Find a user by their email address using GSI1.
 *
 * @param client - DynamoDB Document client
 * @param tableName - DynamoDB table name
 * @param email - The user's email address
 * @returns UserItem or null if not found
 */
export async function getUserByEmail(
    client: DynamoDBDocumentClient,
    tableName: string,
    email: string
): Promise<UserItem | null> {
    const result = await withRetry(async () => {
        return client.send(
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
    });

    if (!result.Items || result.Items.length === 0) {
        return null;
    }

    return result.Items[0] as UserItem;
}

/**
 * Save or update a user.
 *
 * @param client - DynamoDB Document client
 * @param tableName - DynamoDB table name
 * @param user - The UserItem to save
 */
export async function saveUser(
    client: DynamoDBDocumentClient,
    tableName: string,
    user: UserItem
): Promise<void> {
    const now = new Date().toISOString();

    await withRetry(async () => {
        return client.send(
            new PutCommand({
                TableName: tableName,
                Item: {
                    ...user,
                    PK: `USER#${user.sub}`,
                    SK: 'PROFILE',
                    GSI1PK: `EMAIL#${user.email.toLowerCase()}`,
                    GSI1SK: 'USER',
                    entityType: 'USER',
                    updatedAt: now,
                    createdAt: user.createdAt || now,
                },
            })
        );
    });
}
