/**
 * RFC 7592 - Update Client (PUT /connect/register/:clientId)
 *
 * Implements OAuth 2.0 Dynamic Client Registration Management Protocol.
 *
 * Security:
 * - Requires valid registration_access_token or admin token with client:manage scope
 * - client_id cannot be changed
 * - client_secret can be rotated (new secret generated)
 *
 * @see RFC 7592 Section 2.2 - Client Update Request
 */

import type { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import type { APIGatewayProxyResultV2 } from 'aws-lambda';
import { success, error, hashToken, generateSecureRandom, AuditLogger } from '@oauth-server/shared';
import type { ClientItem } from '../../../shared_types/client';
import type { ClientRegistrationRequest, ClientRegistrationResponse, EnvConfig } from './types';
import { validateClientRegistration } from './validation';
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
// Update Client Handler
// =============================================================================

/**
 * Handle PUT /connect/register/:clientId - Update client configuration.
 *
 * @param clientId - The client_id from the URL path
 * @param body - Parsed JSON request body
 * @param authHeader - Authorization header (Bearer token)
 * @param config - Environment configuration
 * @param client - DynamoDB document client
 * @param audit - Audit logger
 * @returns API Gateway response
 */
export async function handleUpdateClient(
    clientId: string,
    body: ClientRegistrationRequest,
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

    const existingClient = result.Item as ClientItem & Record<string, unknown>;

    // Verify registration access token
    if (!existingClient.registrationAccessTokenHash ||
        !verifyRegistrationToken(token, existingClient.registrationAccessTokenHash as string)) {
        audit.log({
            action: 'CLIENT_UPDATE_FAILED',
            actor: { type: 'ANONYMOUS' },
            details: { clientId, reason: 'invalid_registration_token' },
        });
        return error(401, 'invalid_token', 'Invalid registration access token');
    }

    // Validate new metadata
    const validation = validateClientRegistration(body);
    if (!validation.valid || !validation.metadata) {
        return error(400, validation.errorCode || 'invalid_client_metadata', validation.error);
    }

    const metadata = validation.metadata;
    const now = new Date();
    const nowIso = now.toISOString();

    // Determine if we need to rotate the secret
    // If client type changes from PUBLIC to CONFIDENTIAL, generate new secret
    const needsNewSecret = metadata.clientType === 'CONFIDENTIAL' && !existingClient.clientSecretHash;
    const clientSecret = needsNewSecret ? generateSecureRandom(32) : undefined;
    const clientSecretHash = clientSecret ? hashToken(clientSecret) : existingClient.clientSecretHash;

    // Build updated ClientItem
    const updatedClient: ClientItem & Record<string, unknown> = {
        ...existingClient,
        clientName: metadata.clientName,
        clientType: metadata.clientType,
        redirectUris: metadata.redirectUris,
        grantTypes: metadata.grantTypes,
        allowedScopes: metadata.scope.split(' ').filter(Boolean),
        authStrategyId: metadata.enabledStrategies[0]?.toLowerCase() as 'password' | 'saml' | 'oidc' || 'password',
        updatedAt: nowIso,
        clientSecretHash,
        tokenEndpointAuthMethod: metadata.tokenEndpointAuthMethod,
        responseTypes: metadata.responseTypes,
        enabledStrategies: metadata.enabledStrategies,
        clientUri: metadata.clientUri,
        logoUri: metadata.logoUri,
        tosUri: metadata.tosUri,
        policyUri: metadata.policyUri,
        contacts: metadata.contacts,
        softwareId: metadata.softwareId,
        softwareVersion: metadata.softwareVersion,
    };

    // Save to DynamoDB
    await client.send(
        new PutCommand({
            TableName: config.tableName,
            Item: updatedClient,
        })
    );

    // Audit log
    audit.log({
        action: 'CLIENT_UPDATED',
        actor: { type: 'CLIENT', clientId },
        details: {
            clientId,
            clientName: metadata.clientName,
            changes: {
                redirectUris: metadata.redirectUris,
                grantTypes: metadata.grantTypes,
                secretRotated: needsNewSecret,
            },
        },
    });

    // Build response
    const response: ClientRegistrationResponse = {
        client_id: clientId,
        client_id_issued_at: existingClient.clientIdIssuedAt as number,
        // Only return new secret if it was rotated
        ...(clientSecret && {
            client_secret: clientSecret,
            client_secret_expires_at: 0,
        }),
        registration_client_uri: `${config.registrationEndpoint}/${clientId}`,
        client_name: metadata.clientName,
        redirect_uris: metadata.redirectUris,
        grant_types: metadata.grantTypes,
        response_types: metadata.responseTypes,
        scope: metadata.scope,
        token_endpoint_auth_method: metadata.tokenEndpointAuthMethod,
        enabled_strategies: metadata.enabledStrategies,
        ...(metadata.clientUri && { client_uri: metadata.clientUri }),
        ...(metadata.logoUri && { logo_uri: metadata.logoUri }),
        ...(metadata.tosUri && { tos_uri: metadata.tosUri }),
        ...(metadata.policyUri && { policy_uri: metadata.policyUri }),
        ...(metadata.contacts && { contacts: metadata.contacts }),
        ...(metadata.softwareId && { software_id: metadata.softwareId }),
        ...(metadata.softwareVersion && { software_version: metadata.softwareVersion }),
    };

    return success(response);
}
