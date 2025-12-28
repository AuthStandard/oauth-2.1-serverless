/**
 * OAuth Server - Client Storage Operations
 *
 * DynamoDB operations for OAuth client entities.
 *
 * Key Pattern:
 *   PK: CLIENT#<client_id>
 *   SK: CONFIG
 *   GSI1PK: CLIENTS
 *   GSI1SK: <client_id>
 *
 * @module storage/client-operations
 */

import { DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import type { ClientItem } from '../../../shared_types/schema';
import { withRetry } from './retry';

/**
 * Retrieve an OAuth client by its client_id.
 *
 * @param client - DynamoDB Document client
 * @param tableName - DynamoDB table name
 * @param clientId - The OAuth client identifier
 * @returns ClientItem or null if not found
 */
export async function getClient(
    client: DynamoDBDocumentClient,
    tableName: string,
    clientId: string
): Promise<ClientItem | null> {
    const result = await withRetry(async () => {
        return client.send(
            new GetCommand({
                TableName: tableName,
                Key: {
                    PK: `CLIENT#${clientId}`,
                    SK: 'CONFIG',
                },
            })
        );
    });

    if (!result.Item) {
        return null;
    }

    return result.Item as ClientItem;
}

/**
 * Save or update an OAuth client.
 *
 * @param client - DynamoDB Document client
 * @param tableName - DynamoDB table name
 * @param clientItem - The ClientItem to save
 */
export async function saveClient(
    client: DynamoDBDocumentClient,
    tableName: string,
    clientItem: ClientItem
): Promise<void> {
    const now = new Date().toISOString();

    await withRetry(async () => {
        return client.send(
            new PutCommand({
                TableName: tableName,
                Item: {
                    ...clientItem,
                    PK: `CLIENT#${clientItem.clientId}`,
                    SK: 'CONFIG',
                    GSI1PK: 'CLIENTS',
                    GSI1SK: clientItem.clientId,
                    entityType: 'CLIENT',
                    updatedAt: now,
                    createdAt: clientItem.createdAt || now,
                },
            })
        );
    });
}
