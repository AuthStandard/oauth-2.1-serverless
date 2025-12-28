/**
 * RFC 7592 - Delete Client (DELETE /connect/register/:clientId)
 *
 * Implements OAuth 2.0 Dynamic Client Registration Management Protocol.
 *
 * Security:
 * - Requires valid registration_access_token or admin token with client:manage scope
 * - Deletion is permanent and cannot be undone
 *
 * @see RFC 7592 Section 2.3 - Client Delete Request
 */

import type { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { GetCommand, DeleteCommand } from '@aws-sdk/lib-dynamodb';
import type { APIGatewayProxyResultV2 } from 'aws-lambda';
import { noContent, error, hashToken, AuditLogger } from '@oauth-server/shared';
import type { ClientItem } from '../../../shared_types/client';
import type { EnvConfig } from './types';
import { timingSafeEqual } from 'node:crypto';

// =============================================================================
// Token Verification
// =============================================================================

function verifyRegistrationToken(providedToken: string, storedHash: string): boolean {
    const providedHash = hashToken(providedToken);
    if (providedHash.length !== storedHash.length) return false;
    try {
        return timingSafeEqual(
            Buffer.from(providedHash, 'utf-8'),
            Buffer.from(storedHash, 'utf-8')
        );
    } catch {
        return false;
    }
}

// =============================================================================
// Delete Client Handler
// =============================================================================

/**
 * Handle DELETE /connect/register/:clientId - Delete client.
 *
 * @param clientId - The client_id from the URL path
 * @param authHeader - Authorization header (Bearer token)
 * @param config - Environment configuration
 * @param client - DynamoDB document client
 * @param audit - Audit logger
 * @returns API Gateway response
 */
export async function handleDeleteClient(
    clientId: string,
    authHeader: string | undefined,
    config: EnvConfig,
    client: DynamoDBDocumentClient,
    audit: AuditLogger
): Promise<APIGatewayProxyResultV2> {
    // Extract Bearer token
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return error(401, 'invalid_token', 'Missing or invalid Authorization header');
    }

    const token = authHeader.slice(7);

    // Fetch existing client
    const result = await client.send(
        new GetCommand({
            TableName: config.tableName,
            Key: {
                PK: `CLIENT#${clientId}`,
                SK: 'CONFIG',
            },
        })
    );

    if (!result.Item) {
        return error(404, 'invalid_request', 'Client not found');
    }

    const existingClient = result.Item as ClientItem & {
        registrationAccessTokenHash?: string;
    };

    // Verify registration access token
    if (!existingClient.registrationAccessTokenHash ||
        !verifyRegistrationToken(token, existingClient.registrationAccessTokenHash)) {
        audit.log({
            action: 'CLIENT_DELETE_FAILED',
            actor: { type: 'ANONYMOUS' },
            details: { clientId, reason: 'invalid_registration_token' },
        });
        return error(401, 'invalid_token', 'Invalid registration access token');
    }

    // Delete from DynamoDB
    await client.send(
        new DeleteCommand({
            TableName: config.tableName,
            Key: {
                PK: `CLIENT#${clientId}`,
                SK: 'CONFIG',
            },
        })
    );

    // Audit log
    audit.log({
        action: 'CLIENT_DELETED',
        actor: { type: 'CLIENT', clientId },
        details: {
            clientId,
            clientName: existingClient.clientName,
        },
    });

    // RFC 7592 Section 2.3: Return 204 No Content on successful deletion
    return noContent();
}
