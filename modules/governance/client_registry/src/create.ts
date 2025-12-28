/**
 * RFC 7591 - Create Client (POST /connect/register)
 *
 * Implements OAuth 2.0 Dynamic Client Registration Protocol.
 *
 * Security:
 * - client_secret is generated with 32 bytes of entropy (256 bits)
 * - client_secret is hashed with SHA-256 before storage (never stored plaintext)
 * - Registration access token is generated for RFC 7592 management
 *
 * @see RFC 7591 Section 3.1 - Client Registration Request
 * @see RFC 7591 Section 3.2 - Client Registration Response
 */

import type { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { PutCommand } from '@aws-sdk/lib-dynamodb';
import type { APIGatewayProxyResultV2 } from 'aws-lambda';
import { created, error, hashToken, generateSecureRandom, AuditLogger } from '@oauth-server/shared';
import type { ClientItem, TokenLifetimes } from '../../../shared_types/client';
import type { ClientRegistrationRequest, ClientRegistrationResponse, EnvConfig } from './types';
import { validateClientRegistration } from './validation';

// =============================================================================
// Constants
// =============================================================================

/** Default token lifetimes for new clients */
const DEFAULT_TOKEN_LIFETIMES: TokenLifetimes = {
    accessToken: 3600,      // 1 hour
    refreshToken: 2592000,  // 30 days
    authorizationCode: 600, // 10 minutes
};

// =============================================================================
// UUID Generation
// =============================================================================

/**
 * Generate a UUID v4 for client_id.
 * Uses crypto.randomBytes for secure random generation.
 */
function generateClientId(): string {
    const bytes = Buffer.from(generateSecureRandom(16), 'base64url');
    // Set version (4) and variant (RFC 4122)
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    const hex = bytes.toString('hex');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

// =============================================================================
// Create Client Handler
// =============================================================================

/**
 * Handle POST /connect/register - Create a new OAuth client.
 *
 * @param body - Parsed JSON request body
 * @param config - Environment configuration
 * @param client - DynamoDB document client
 * @param audit - Audit logger
 * @returns API Gateway response
 */
export async function handleCreateClient(
    body: ClientRegistrationRequest,
    config: EnvConfig,
    client: DynamoDBDocumentClient,
    audit: AuditLogger
): Promise<APIGatewayProxyResultV2> {
    // Validate client metadata
    const validation = validateClientRegistration(body);
    if (!validation.valid || !validation.metadata) {
        return error(400, validation.errorCode || 'invalid_client_metadata', validation.error);
    }

    const metadata = validation.metadata;
    const now = new Date();
    const nowIso = now.toISOString();
    const issuedAt = Math.floor(now.getTime() / 1000);

    // Generate client credentials
    const clientId = generateClientId();
    const clientSecret = metadata.clientType === 'CONFIDENTIAL' ? generateSecureRandom(32) : undefined;
    const clientSecretHash = clientSecret ? hashToken(clientSecret) : undefined;

    // Generate registration access token for RFC 7592 management
    const registrationAccessToken = generateSecureRandom(32);
    const registrationAccessTokenHash = hashToken(registrationAccessToken);

    // Build ClientItem for DynamoDB
    const clientItem: ClientItem = {
        PK: `CLIENT#${clientId}`,
        SK: 'CONFIG',
        GSI1PK: 'CLIENTS',
        GSI1SK: clientId,
        entityType: 'CLIENT',
        clientId,
        clientName: metadata.clientName,
        clientType: metadata.clientType,
        redirectUris: metadata.redirectUris,
        grantTypes: metadata.grantTypes,
        allowedScopes: metadata.scope.split(' ').filter(Boolean),
        authStrategyId: metadata.enabledStrategies[0]?.toLowerCase() as 'password' | 'saml' | 'oidc' || 'password',
        tokenLifetimes: DEFAULT_TOKEN_LIFETIMES,
        createdAt: nowIso,
        updatedAt: nowIso,
        // Store hashed secret (never plaintext)
        ...(clientSecretHash && { clientSecretHash }),
        // Store hashed registration access token
        registrationAccessTokenHash,
        // Additional metadata
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
        clientIdIssuedAt: issuedAt,
    } as ClientItem & Record<string, unknown>;

    // Save to DynamoDB
    await client.send(
        new PutCommand({
            TableName: config.tableName,
            Item: clientItem,
            // Ensure client_id doesn't already exist
            ConditionExpression: 'attribute_not_exists(PK)',
        })
    );

    // Audit log
    audit.log({
        action: 'CLIENT_CREATED',
        actor: { type: 'SYSTEM' },
        details: {
            clientId,
            clientName: metadata.clientName,
            clientType: metadata.clientType,
            grantTypes: metadata.grantTypes,
            redirectUris: metadata.redirectUris,
        },
    });

    // Build response (RFC 7591 Section 3.2.1)
    const response: ClientRegistrationResponse = {
        client_id: clientId,
        client_id_issued_at: issuedAt,
        // Return plaintext secret ONLY in this response (never again)
        ...(clientSecret && {
            client_secret: clientSecret,
            client_secret_expires_at: 0, // Never expires
        }),
        // RFC 7592 management endpoints
        registration_access_token: registrationAccessToken,
        registration_client_uri: `${config.registrationEndpoint}/${clientId}`,
        // Echo back registered metadata
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

    return created(response);
}
