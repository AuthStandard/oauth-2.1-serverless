/**
 * OAuth Server - TOTP MFA Strategy Database Operations
 *
 * DynamoDB operations for the TOTP multi-factor authentication flow.
 * Implements Single Table Design patterns.
 */

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
    DynamoDBDocumentClient,
    GetCommand,
    PutCommand,
    UpdateCommand,
    DeleteCommand,
} from '@aws-sdk/lib-dynamodb';
import type { MfaSetupTokenItem, UserMfaConfig } from './types';

// =============================================================================
// DynamoDB Client Singleton
// =============================================================================

let docClient: DynamoDBDocumentClient | null = null;

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
// MFA Setup Token Operations
// =============================================================================

/**
 * Save MFA setup token for enrollment verification.
 * Token expires after 10 minutes.
 */
export async function saveMfaSetupToken(
    tableName: string,
    params: {
        userId: string;
        secret: string;
        backupCodes: string[];
    }
): Promise<void> {
    const client = getDocClient();
    const now = new Date().toISOString();
    const ttl = Math.floor(Date.now() / 1000) + 600; // 10 minutes

    const item: MfaSetupTokenItem = {
        PK: `MFA_SETUP#${params.userId}`,
        SK: 'METADATA',
        entityType: 'MFA_SETUP_TOKEN',
        userId: params.userId,
        secret: params.secret,
        backupCodes: params.backupCodes,
        createdAt: now,
        ttl,
    };

    await client.send(
        new PutCommand({
            TableName: tableName,
            Item: item,
        })
    );
}

/**
 * Get MFA setup token for verification.
 */
export async function getMfaSetupToken(
    tableName: string,
    userId: string
): Promise<MfaSetupTokenItem | null> {
    const client = getDocClient();
    const result = await client.send(
        new GetCommand({
            TableName: tableName,
            Key: { PK: `MFA_SETUP#${userId}`, SK: 'METADATA' },
        })
    );
    return (result.Item as MfaSetupTokenItem) || null;
}

/**
 * Delete MFA setup token after successful enrollment.
 */
export async function deleteMfaSetupToken(
    tableName: string,
    userId: string
): Promise<void> {
    const client = getDocClient();
    await client.send(
        new DeleteCommand({
            TableName: tableName,
            Key: { PK: `MFA_SETUP#${userId}`, SK: 'METADATA' },
        })
    );
}

// =============================================================================
// User MFA Configuration Operations
// =============================================================================

/**
 * Get user's MFA configuration.
 */
export async function getUserMfaConfig(
    tableName: string,
    userId: string
): Promise<UserMfaConfig | null> {
    const client = getDocClient();
    const result = await client.send(
        new GetCommand({
            TableName: tableName,
            Key: { PK: `USER#${userId}`, SK: 'PROFILE' },
            ProjectionExpression: 'mfaEnabled, mfaMethod, totpSecret, backupCodesHashes, mfaEnabledAt',
        })
    );

    if (!result.Item) {
        return null;
    }

    return {
        mfaEnabled: result.Item.mfaEnabled || false,
        mfaMethod: result.Item.mfaMethod,
        totpSecret: result.Item.totpSecret,
        backupCodesHashes: result.Item.backupCodesHashes,
        mfaEnabledAt: result.Item.mfaEnabledAt,
    };
}

/**
 * Enable MFA for a user after successful verification.
 */
export async function enableUserMfa(
    tableName: string,
    userId: string,
    totpSecret: string,
    backupCodesHashes: string[]
): Promise<boolean> {
    const client = getDocClient();
    const now = new Date().toISOString();

    try {
        await client.send(
            new UpdateCommand({
                TableName: tableName,
                Key: { PK: `USER#${userId}`, SK: 'PROFILE' },
                UpdateExpression: 'SET mfaEnabled = :enabled, mfaMethod = :method, totpSecret = :secret, backupCodesHashes = :codes, mfaEnabledAt = :now, updatedAt = :now',
                ConditionExpression: 'attribute_exists(PK)',
                ExpressionAttributeValues: {
                    ':enabled': true,
                    ':method': 'totp',
                    ':secret': totpSecret,
                    ':codes': backupCodesHashes,
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

/**
 * Disable MFA for a user.
 */
export async function disableUserMfa(
    tableName: string,
    userId: string
): Promise<boolean> {
    const client = getDocClient();
    const now = new Date().toISOString();

    try {
        await client.send(
            new UpdateCommand({
                TableName: tableName,
                Key: { PK: `USER#${userId}`, SK: 'PROFILE' },
                UpdateExpression: 'SET mfaEnabled = :disabled, updatedAt = :now REMOVE mfaMethod, totpSecret, backupCodesHashes, mfaEnabledAt',
                ConditionExpression: 'attribute_exists(PK) AND mfaEnabled = :enabled',
                ExpressionAttributeValues: {
                    ':disabled': false,
                    ':enabled': true,
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

/**
 * Use a backup code (mark as used by removing from list).
 */
export async function useBackupCode(
    tableName: string,
    userId: string,
    codeHash: string
): Promise<boolean> {
    const client = getDocClient();
    const now = new Date().toISOString();

    try {
        await client.send(
            new UpdateCommand({
                TableName: tableName,
                Key: { PK: `USER#${userId}`, SK: 'PROFILE' },
                UpdateExpression: 'DELETE backupCodesHashes :codeHash SET updatedAt = :now',
                ConditionExpression: 'contains(backupCodesHashes, :hash)',
                ExpressionAttributeValues: {
                    ':codeHash': new Set([codeHash]),
                    ':hash': codeHash,
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
