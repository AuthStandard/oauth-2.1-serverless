/**
 * OAuth Server - SAML Provider Storage Operations
 *
 * DynamoDB operations for SAML Identity Provider configuration entities.
 *
 * Key Pattern:
 *   PK: SAML#<issuer>
 *   SK: CONFIG
 *   GSI1PK: SAML_PROVIDERS
 *   GSI1SK: <issuer>
 *
 * @module storage/saml-provider-operations
 */

import {
    DynamoDBDocumentClient,
    GetCommand,
    PutCommand,
    DeleteCommand,
    QueryCommand,
} from '@aws-sdk/lib-dynamodb';
import type { SAMLProviderItem } from '../../../shared_types/schema';
import { withRetry } from './retry';

/**
 * Retrieve a SAML provider by its issuer (Entity ID).
 *
 * @param client - DynamoDB Document client
 * @param tableName - DynamoDB table name
 * @param issuer - The SAML IdP Entity ID
 * @returns SAMLProviderItem or null if not found
 */
export async function getSAMLProvider(
    client: DynamoDBDocumentClient,
    tableName: string,
    issuer: string
): Promise<SAMLProviderItem | null> {
    const result = await withRetry(async () => {
        return client.send(
            new GetCommand({
                TableName: tableName,
                Key: {
                    PK: `SAML#${issuer}`,
                    SK: 'CONFIG',
                },
            })
        );
    });

    if (!result.Item) {
        return null;
    }

    return result.Item as SAMLProviderItem;
}

/**
 * Save or update a SAML provider configuration.
 *
 * @param client - DynamoDB Document client
 * @param tableName - DynamoDB table name
 * @param provider - The SAMLProviderItem to save
 */
export async function saveSAMLProvider(
    client: DynamoDBDocumentClient,
    tableName: string,
    provider: SAMLProviderItem
): Promise<void> {
    const now = new Date().toISOString();

    await withRetry(async () => {
        return client.send(
            new PutCommand({
                TableName: tableName,
                Item: {
                    ...provider,
                    PK: `SAML#${provider.issuer}`,
                    SK: 'CONFIG',
                    GSI1PK: 'SAML_PROVIDERS',
                    GSI1SK: provider.issuer,
                    entityType: 'SAML_PROVIDER',
                    updatedAt: now,
                    createdAt: provider.createdAt || now,
                },
            })
        );
    });
}

/**
 * Delete a SAML provider configuration.
 *
 * @param client - DynamoDB Document client
 * @param tableName - DynamoDB table name
 * @param issuer - The SAML IdP Entity ID
 */
export async function deleteSAMLProvider(
    client: DynamoDBDocumentClient,
    tableName: string,
    issuer: string
): Promise<void> {
    await withRetry(async () => {
        return client.send(
            new DeleteCommand({
                TableName: tableName,
                Key: {
                    PK: `SAML#${issuer}`,
                    SK: 'CONFIG',
                },
            })
        );
    });
}

/**
 * List all enabled SAML providers.
 *
 * @param client - DynamoDB Document client
 * @param tableName - DynamoDB table name
 * @returns Array of enabled SAMLProviderItems
 */
export async function listEnabledSAMLProviders(
    client: DynamoDBDocumentClient,
    tableName: string
): Promise<SAMLProviderItem[]> {
    const providers: SAMLProviderItem[] = [];
    let lastEvaluatedKey: Record<string, unknown> | undefined;

    do {
        const result = await withRetry(async () => {
            return client.send(
                new QueryCommand({
                    TableName: tableName,
                    IndexName: 'GSI1',
                    KeyConditionExpression: 'GSI1PK = :pk',
                    FilterExpression: 'enabled = :enabled',
                    ExpressionAttributeValues: {
                        ':pk': 'SAML_PROVIDERS',
                        ':enabled': true,
                    },
                    ExclusiveStartKey: lastEvaluatedKey,
                })
            );
        });

        if (result.Items) {
            providers.push(...(result.Items as SAMLProviderItem[]));
        }

        lastEvaluatedKey = result.LastEvaluatedKey;
    } while (lastEvaluatedKey);

    return providers;
}
