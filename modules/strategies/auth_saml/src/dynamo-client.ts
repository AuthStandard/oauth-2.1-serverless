/**
 * SAML Strategy - DynamoDB Client
 *
 * Singleton DynamoDB Document Client with connection reuse.
 */

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';

// =============================================================================
// Singleton Client
// =============================================================================

let docClient: DynamoDBDocumentClient | null = null;

/**
 * Get or create the DynamoDB Document Client.
 * Uses Lambda execution context reuse for connection pooling.
 *
 * @returns DynamoDB Document Client instance
 */
export function getDocClient(): DynamoDBDocumentClient {
    if (!docClient) {
        const client = new DynamoDBClient({});
        docClient = DynamoDBDocumentClient.from(client, {
            marshallOptions: {
                removeUndefinedValues: true,
            },
        });
    }
    return docClient;
}
