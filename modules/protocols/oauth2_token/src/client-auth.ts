/**
 * OAuth 2.1 Token Endpoint - Client Authentication Adapter
 *
 * Adapts shared client authentication to token endpoint parameter types.
 * Delegates actual authentication logic to @oauth-server/shared.
 *
 * Authentication Methods (OAuth 2.1 Section 2.4):
 * - client_secret_basic: HTTP Basic Authentication (RECOMMENDED)
 * - client_secret_post: POST body credentials
 * - Public clients: Identified by client_id only (no secret required)
 *
 * @module oauth2_token/client-auth
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-14#section-2.4
 */

import type { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import type { APIGatewayProxyResultV2 } from 'aws-lambda';
import {
    authenticateClient as sharedAuthenticateClient,
    extractClientCredentials as sharedExtractClientCredentials,
} from '@oauth-server/shared';
import type { TokenRequestParams, ClientItem } from './types';

// =============================================================================
// Types
// =============================================================================

/**
 * Result of client authentication attempt.
 */
export interface ClientAuthResult {
    /** Whether authentication was successful */
    readonly valid: boolean;

    /** Authenticated client configuration (if valid) */
    readonly clientItem?: ClientItem;

    /** Error response to return (if invalid) */
    readonly error?: APIGatewayProxyResultV2;
}

// =============================================================================
// Credential Extraction
// =============================================================================

/**
 * Extract client credentials from token request.
 *
 * Per OAuth 2.1 Section 2.4.1, credentials can be provided via:
 * 1. HTTP Basic Authentication header (RECOMMENDED)
 * 2. Request body parameters (client_id, client_secret)
 *
 * @param params - Parsed token request parameters
 * @param authHeader - Authorization header value
 * @returns Extracted client credentials
 */
export function extractClientCredentials(
    params: TokenRequestParams,
    authHeader: string | undefined
): { clientId?: string; clientSecret?: string } {
    const urlParams = new URLSearchParams();
    if (params.clientId) urlParams.set('client_id', params.clientId);
    if (params.clientSecret) urlParams.set('client_secret', params.clientSecret);
    return sharedExtractClientCredentials(urlParams, authHeader);
}

// =============================================================================
// Client Authentication
// =============================================================================

/**
 * Authenticate an OAuth client per OAuth 2.1 Section 2.4.
 *
 * Authentication requirements depend on client type:
 * - Confidential clients: MUST authenticate with client_secret
 * - Public clients: Only validates client_id exists
 *
 * @param params - Parsed token request parameters
 * @param authHeader - Authorization header value
 * @param client - DynamoDB document client
 * @param tableName - DynamoDB table name
 * @returns Authentication result with client data or error
 */
export async function authenticateClient(
    params: TokenRequestParams,
    authHeader: string | undefined,
    client: DynamoDBDocumentClient,
    tableName: string
): Promise<ClientAuthResult> {
    const urlParams = new URLSearchParams();
    if (params.clientId) urlParams.set('client_id', params.clientId);
    if (params.clientSecret) urlParams.set('client_secret', params.clientSecret);

    const result = await sharedAuthenticateClient(urlParams, authHeader, client, tableName);

    return {
        valid: result.valid,
        clientItem: result.clientItem as ClientItem | undefined,
        error: result.error,
    };
}
