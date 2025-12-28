/**
 * RFC 7592 - Read Client (GET /connect/register/:clientId)
 *
 * Implements OAuth 2.0 Dynamic Client Registration Management Protocol.
 *
 * Security:
 * - Requires valid registration_access_token or admin token with client:manage scope
 * - Never returns client_secret (only shown once during registration)
 *
 * @see RFC 7592 Section 2.1 - Client Read Request
 * @see RFC 7592 Section 3 - Client Information Response
 */

import type { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { GetCommand } from '@aws-sdk/lib-dynamodb';
import type { APIGatewayProxyResultV2 } from 'aws-lambda';
import { success, error, hashToken, AuditLogger } from '@oauth-server/shared';
import type { ClientItem } from '../../../shared_types/client';
import type { ClientReadResponse, EnvConfig } from './types';
import { timingSafeEqual } from 'node:crypto';

// =============================================================================
// Token Verification
// =============================================================================

/**
 * Verify the registration access token using constant-time comparison.
 */
function verifyRegistrationToken(providedToken: string, storedHash: string): boolean {
    const providedHash = hashToken(providedToken);

    if (providedHash.length !== storedHash.length) {
        return false;
    }

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
// Read Client Handler
// =============================================================================

/**
 * Handle GET /connect/register/:clientId - Read client configuration.
 *
 * @param clientId - The client_id from the URL path
 * @param authHeader - Authorization header (Bearer token)
 * @param config - Environment configuration
 * @param client - DynamoDB document client
 * @param audit - Audit logger
 * @returns API Gateway response
 */
export async function handleReadClient(
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

    const token = authHeader.slice(7); // Remove 'Bearer ' prefix

    // Fetch client from DynamoDB
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

    const clientItem = result.Item as ClientItem & {
        registrationAccessTokenHash?: string;
        tokenEndpointAuthMethod?: string;
        responseTypes?: string[];
        enabledStrategies?: string[];
        clientUri?: string;
        logoUri?: string;
        tosUri?: string;
        policyUri?: string;
        contacts?: string[];
        softwareId?: string;
        softwareVersion?: string;
        clientIdIssuedAt?: number;
    };

    // Verify registration access token
    // Note: Admin tokens with client:manage scope are a future enhancement.
    // For now, only registration_access_token is supported per RFC 7592.
    if (!clientItem.registrationAccessTokenHash) {
        return error(401, 'invalid_token', 'Client does not have a registration access token');
    }

    if (!verifyRegistrationToken(token, clientItem.registrationAccessTokenHash)) {
        audit.log({
            action: 'CLIENT_READ_FAILED',
            actor: { type: 'ANONYMOUS' },
            details: {
                clientId,
                reason: 'invalid_registration_token',
            },
        });
        return error(401, 'invalid_token', 'Invalid registration access token');
    }

    // Audit log
    audit.log({
        action: 'CLIENT_READ',
        actor: { type: 'CLIENT', clientId },
        details: { clientId },
    });

    // Build response (RFC 7592 Section 3)
    // Note: client_secret is NEVER returned
    const response: ClientReadResponse = {
        client_id: clientItem.clientId,
        client_id_issued_at: clientItem.clientIdIssuedAt,
        registration_client_uri: `${config.registrationEndpoint}/${clientId}`,
        client_name: clientItem.clientName,
        redirect_uris: [...clientItem.redirectUris],
        grant_types: [...clientItem.grantTypes],
        response_types: clientItem.responseTypes ? [...clientItem.responseTypes] : ['code'],
        scope: clientItem.allowedScopes.join(' '),
        token_endpoint_auth_method: clientItem.tokenEndpointAuthMethod || 'client_secret_basic',
        enabled_strategies: clientItem.enabledStrategies,
        ...(clientItem.clientUri && { client_uri: clientItem.clientUri }),
        ...(clientItem.logoUri && { logo_uri: clientItem.logoUri }),
        ...(clientItem.tosUri && { tos_uri: clientItem.tosUri }),
        ...(clientItem.policyUri && { policy_uri: clientItem.policyUri }),
        ...(clientItem.contacts && { contacts: clientItem.contacts }),
        ...(clientItem.softwareId && { software_id: clientItem.softwareId }),
        ...(clientItem.softwareVersion && { software_version: clientItem.softwareVersion }),
    };

    return success(response);
}
