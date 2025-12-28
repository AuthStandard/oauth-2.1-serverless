/**
 * OIDC RP-Initiated Logout - Client Operations
 *
 * DynamoDB operations for client configuration retrieval.
 *
 * Key Pattern: PK=CLIENT#<client_id>, SK=CONFIG
 *
 * @see https://openid.net/specs/openid-connect-rpinitiated-1_0.html
 */

import { DynamoDBDocumentClient, GetCommand } from '@aws-sdk/lib-dynamodb';
import type { ClientRecord } from './types';

/**
 * Retrieve client configuration from DynamoDB.
 *
 * @param client - DynamoDB Document client
 * @param tableName - DynamoDB table name
 * @param clientId - OAuth2 client identifier
 * @returns Client configuration or null if not found
 */
export async function getClient(
    client: DynamoDBDocumentClient,
    tableName: string,
    clientId: string
): Promise<ClientRecord | null> {
    const result = await client.send(
        new GetCommand({
            TableName: tableName,
            Key: {
                PK: `CLIENT#${clientId}`,
                SK: 'CONFIG',
            },
            ProjectionExpression: 'clientId, clientName, redirectUris, postLogoutRedirectUris',
        })
    );

    if (!result.Item) {
        return null;
    }

    return result.Item as ClientRecord;
}
