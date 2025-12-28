/**
 * OAuth Server - Authorization Code Storage Operations
 *
 * DynamoDB operations for authorization code entities.
 * Implements single-use semantics with conditional updates.
 *
 * Key Pattern:
 *   PK: CODE#<code>
 *   SK: METADATA
 *   GSI1PK: CLIENT#<client_id>
 *   GSI1SK: CODE#<timestamp>
 *
 * @module storage/auth-code-operations
 */

import { DynamoDBDocumentClient, GetCommand, PutCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import type { AuthCodeItem } from '../../../shared_types/schema';
import { withRetry } from './retry';

/**
 * Retrieve an authorization code.
 *
 * @param client - DynamoDB Document client
 * @param tableName - DynamoDB table name
 * @param code - The authorization code value
 * @returns AuthCodeItem or null if not found
 */
export async function getAuthCode(
    client: DynamoDBDocumentClient,
    tableName: string,
    code: string
): Promise<AuthCodeItem | null> {
    const result = await withRetry(async () => {
        return client.send(
            new GetCommand({
                TableName: tableName,
                Key: {
                    PK: `CODE#${code}`,
                    SK: 'METADATA',
                },
            })
        );
    });

    if (!result.Item) {
        return null;
    }

    return result.Item as AuthCodeItem;
}

/**
 * Save a new authorization code.
 *
 * Authorization codes are short-lived credentials that MUST expire shortly
 * after issuance. The TTL is calculated from the authCode.ttl field which
 * should be set by the caller based on client configuration.
 *
 * @param client - DynamoDB Document client
 * @param tableName - DynamoDB table name
 * @param authCode - The AuthCodeItem to save (must include ttl for automatic expiration)
 *
 * @see OAuth 2.1 Section 4.1.2 - Authorization codes SHOULD expire shortly after issuance
 */
export async function saveAuthCode(
    client: DynamoDBDocumentClient,
    tableName: string,
    authCode: AuthCodeItem
): Promise<void> {
    const now = new Date().toISOString();

    await withRetry(async () => {
        return client.send(
            new PutCommand({
                TableName: tableName,
                Item: {
                    ...authCode,
                    PK: `CODE#${authCode.code}`,
                    SK: 'METADATA',
                    GSI1PK: `CLIENT#${authCode.clientId}`,
                    GSI1SK: `CODE#${now}`,
                    entityType: 'AUTH_CODE',
                    used: authCode.used ?? false,
                    updatedAt: now,
                    createdAt: authCode.createdAt || now,
                },
            })
        );
    });
}

/**
 * Mark an authorization code as used (consumed).
 * Uses conditional update to prevent replay attacks.
 *
 * Per OAuth 2.1 Section 4.1.2, authorization codes MUST be single-use.
 * If an authorization code is used more than once, the authorization server
 * MUST deny the request and SHOULD revoke all tokens previously issued
 * based on that authorization code.
 *
 * @param client - DynamoDB Document client
 * @param tableName - DynamoDB table name
 * @param code - The authorization code value
 * @returns true if successfully consumed, false if already used or not found
 */
export async function consumeAuthCode(
    client: DynamoDBDocumentClient,
    tableName: string,
    code: string
): Promise<boolean> {
    try {
        await withRetry(async () => {
            return client.send(
                new UpdateCommand({
                    TableName: tableName,
                    Key: {
                        PK: `CODE#${code}`,
                        SK: 'METADATA',
                    },
                    UpdateExpression: 'SET #used = :true, updatedAt = :now',
                    ConditionExpression: 'attribute_exists(PK) AND #used = :false',
                    ExpressionAttributeNames: {
                        '#used': 'used',
                    },
                    ExpressionAttributeValues: {
                        ':true': true,
                        ':false': false,
                        ':now': new Date().toISOString(),
                    },
                })
            );
        });
        return true;
    } catch (error) {
        // ConditionalCheckFailedException means the code was already used or doesn't exist
        if ((error as Error).name === 'ConditionalCheckFailedException') {
            return false;
        }
        throw error;
    }
}
