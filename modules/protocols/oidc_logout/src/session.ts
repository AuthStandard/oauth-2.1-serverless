/**
 * OIDC RP-Initiated Logout - Session Management
 *
 * DynamoDB operations for session termination during logout.
 *
 * Key Patterns:
 *   Session: PK=SESSION#<session_id>, SK=METADATA
 *   User Sessions GSI: GSI1PK=USER#<sub>, GSI1SK=SESSION#<timestamp>
 *
 * @see https://openid.net/specs/openid-connect-rpinitiated-1_0.html
 */

import {
    DynamoDBDocumentClient,
    DeleteCommand,
    QueryCommand,
    BatchWriteCommand,
} from '@aws-sdk/lib-dynamodb';

// =============================================================================
// Session Deletion
// =============================================================================

/**
 * Delete a specific session by ID.
 *
 * Used when the ID token contains a session ID (sid claim).
 * Deletes both login sessions and authenticated sessions.
 *
 * @param client - DynamoDB Document client
 * @param tableName - DynamoDB table name
 * @param sessionId - Session identifier to delete
 */
export async function deleteSession(
    client: DynamoDBDocumentClient,
    tableName: string,
    sessionId: string
): Promise<void> {
    // Delete login session (SESSION#)
    await client.send(
        new DeleteCommand({
            TableName: tableName,
            Key: {
                PK: `SESSION#${sessionId}`,
                SK: 'METADATA',
            },
        })
    );

    // Also delete authenticated session (AUTH_SESSION#)
    await client.send(
        new DeleteCommand({
            TableName: tableName,
            Key: {
                PK: `AUTH_SESSION#${sessionId}`,
                SK: 'METADATA',
            },
        })
    );
}

/**
 * Delete all sessions for a user.
 *
 * Used for complete logout when no specific session ID is available.
 * Queries GSI1 to find all sessions for the user, then batch deletes them.
 * Deletes both login sessions (SESSION#) and authenticated sessions (AUTH_SESSION#).
 *
 * Note: This is a best-effort operation. Sessions have TTL for automatic
 * cleanup, so any missed sessions will be cleaned up eventually.
 *
 * @param client - DynamoDB Document client
 * @param tableName - DynamoDB table name
 * @param sub - User's subject identifier
 * @returns Number of sessions deleted
 */
export async function deleteUserSessions(
    client: DynamoDBDocumentClient,
    tableName: string,
    sub: string
): Promise<number> {
    let deletedCount = 0;

    // Delete login sessions (SESSION#)
    let lastEvaluatedKey: Record<string, unknown> | undefined;
    do {
        const queryResult = await client.send(
            new QueryCommand({
                TableName: tableName,
                IndexName: 'GSI1',
                KeyConditionExpression: 'GSI1PK = :pk AND begins_with(GSI1SK, :sk)',
                ExpressionAttributeValues: {
                    ':pk': `USER#${sub}`,
                    ':sk': 'SESSION#',
                },
                ProjectionExpression: 'PK, SK',
                ExclusiveStartKey: lastEvaluatedKey,
            })
        );

        if (queryResult.Items && queryResult.Items.length > 0) {
            const batches: Record<string, unknown>[][] = [];
            for (let i = 0; i < queryResult.Items.length; i += 25) {
                batches.push(queryResult.Items.slice(i, i + 25));
            }

            for (const batch of batches) {
                const response = await client.send(
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

                const unprocessedCount = response.UnprocessedItems?.[tableName]?.length ?? 0;
                deletedCount += batch.length - unprocessedCount;
            }
        }

        lastEvaluatedKey = queryResult.LastEvaluatedKey;
    } while (lastEvaluatedKey);

    // Delete authenticated sessions (AUTH_SESSION#)
    let authLastEvaluatedKey: Record<string, unknown> | undefined;
    do {
        const authQueryResult = await client.send(
            new QueryCommand({
                TableName: tableName,
                IndexName: 'GSI1',
                KeyConditionExpression: 'GSI1PK = :pk AND begins_with(GSI1SK, :sk)',
                ExpressionAttributeValues: {
                    ':pk': `USER#${sub}`,
                    ':sk': 'AUTH_SESSION#',
                },
                ProjectionExpression: 'PK, SK',
                ExclusiveStartKey: authLastEvaluatedKey,
            })
        );

        if (authQueryResult.Items && authQueryResult.Items.length > 0) {
            const batches: Record<string, unknown>[][] = [];
            for (let i = 0; i < authQueryResult.Items.length; i += 25) {
                batches.push(authQueryResult.Items.slice(i, i + 25));
            }

            for (const batch of batches) {
                const response = await client.send(
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

                const unprocessedCount = response.UnprocessedItems?.[tableName]?.length ?? 0;
                deletedCount += batch.length - unprocessedCount;
            }
        }

        authLastEvaluatedKey = authQueryResult.LastEvaluatedKey;
    } while (authLastEvaluatedKey);

    return deletedCount;
}
