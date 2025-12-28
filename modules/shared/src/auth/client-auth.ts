/**
 * OAuth 2.1 Client Authentication
 *
 * Implements OAuth 2.1 Section 2.4 (Client Authentication) with support for:
 *   - HTTP Basic Authentication (client_secret_basic) - RECOMMENDED per RFC 6749
 *   - POST body credentials (client_secret_post) - Supported for compatibility
 *   - Public clients (no authentication required, identified by client_id only)
 *
 * Security Controls:
 *   - Constant-time comparison prevents timing attacks on secret verification (RFC 9700)
 *   - SHA-256 hashing for stored secrets (secrets never stored in plaintext)
 *   - Strict client type enforcement per OAuth 2.1
 *   - Generic error messages prevent client enumeration attacks
 *
 * @module shared/auth/client-auth
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-14#section-2.4
 * @see https://datatracker.ietf.org/doc/html/rfc9700 (OAuth Security BCP)
 */

import type { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { GetCommand } from '@aws-sdk/lib-dynamodb';
import type { APIGatewayProxyResultV2 } from 'aws-lambda';
import { timingSafeEqual } from 'node:crypto';
import type { ClientItem as ClientItemSchema } from '../../../shared_types/client';
import { hashToken } from '../crypto';
import { invalidRequest, invalidClient } from '../response';

// =============================================================================
// Types
// =============================================================================

/**
 * Client configuration for authentication.
 * Re-exports the schema type for module consumers.
 */
export type ClientItem = Pick<
    ClientItemSchema,
    'clientId' | 'clientType' | 'clientSecretHash' | 'grantTypes' | 'redirectUris' | 'tokenLifetimes'
>;

/**
 * Extracted client credentials from request.
 */
export interface ClientCredentials {
    clientId?: string;
    clientSecret?: string;
}

/**
 * Result of client authentication attempt.
 */
export interface ClientAuthResult {
    /** Whether authentication was successful */
    valid: boolean;
    /** The authenticated client (if valid) */
    clientItem?: ClientItem;
    /** Error response to return (if invalid) */
    error?: APIGatewayProxyResultV2;
}

// =============================================================================
// Credential Extraction
// =============================================================================

/**
 * Extract client credentials from request.
 *
 * Per RFC 6749 Section 2.3.1, credentials can be provided via:
 * 1. HTTP Basic Authentication header (RECOMMENDED)
 * 2. Request body parameters (client_id, client_secret)
 *
 * The Authorization header takes precedence if both are provided.
 *
 * @param params - URL-encoded request parameters
 * @param authHeader - Authorization header value
 * @returns Extracted client credentials
 */
export function extractClientCredentials(
    params: URLSearchParams,
    authHeader?: string
): ClientCredentials {
    // Per RFC 6749 Section 2.3.1, try Authorization header first (Basic auth)
    if (authHeader?.startsWith('Basic ')) {
        try {
            const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
            // Per RFC 7617, the user-id (client_id) cannot contain a colon,
            // but the password (client_secret) can. Split only on first colon.
            const colonIndex = decoded.indexOf(':');
            if (colonIndex > 0) {
                const clientId = decodeURIComponent(decoded.substring(0, colonIndex));
                const clientSecret = decodeURIComponent(decoded.substring(colonIndex + 1));
                return { clientId, clientSecret: clientSecret || undefined };
            }
        } catch {
            // Invalid base64 or encoding - fall through to POST body
        }
    }

    // Fall back to POST body parameters
    return {
        clientId: params.get('client_id') || undefined,
        clientSecret: params.get('client_secret') || undefined,
    };
}

// =============================================================================
// Secret Verification
// =============================================================================

/**
 * Verify client secret using constant-time comparison.
 *
 * Security: Uses timingSafeEqual to prevent timing attacks per RFC 9700 Section 4.8.2.
 * The provided secret is hashed before comparison since we store hashes, not plaintext.
 *
 * @param secret - The client secret to verify
 * @param storedHash - The stored SHA-256 hash of the secret
 * @returns true if the secret matches, false otherwise
 */
export function verifyClientSecret(secret: string, storedHash: string): boolean {
    const providedHash = hashToken(secret);
    try {
        return timingSafeEqual(Buffer.from(providedHash), Buffer.from(storedHash));
    } catch {
        // Buffers of different lengths will throw - return false
        return false;
    }
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
 * @param params - URL-encoded request parameters
 * @param authHeader - Authorization header value
 * @param client - DynamoDB document client
 * @param tableName - DynamoDB table name
 * @returns Authentication result with client data or error
 */
export async function authenticateClient(
    params: URLSearchParams,
    authHeader: string | undefined,
    client: DynamoDBDocumentClient,
    tableName: string
): Promise<ClientAuthResult> {
    const { clientId, clientSecret } = extractClientCredentials(params, authHeader);

    // client_id is always required
    if (!clientId) {
        return {
            valid: false,
            error: invalidRequest('Missing client_id'),
        };
    }

    // Fetch client configuration from DynamoDB
    const clientResult = await client.send(
        new GetCommand({
            TableName: tableName,
            Key: { PK: `CLIENT#${clientId}`, SK: 'CONFIG' },
        })
    );

    if (!clientResult.Item) {
        // Use generic error to prevent client enumeration
        return {
            valid: false,
            error: invalidClient('Client authentication failed'),
        };
    }

    const clientItem = clientResult.Item as ClientItem;

    // Confidential clients MUST authenticate per OAuth 2.1 Section 2.4
    if (clientItem.clientType === 'CONFIDENTIAL') {
        if (!clientSecret) {
            return {
                valid: false,
                error: invalidClient('Client authentication required'),
            };
        }

        // Verify client has a secret configured
        if (!clientItem.clientSecretHash) {
            return {
                valid: false,
                error: invalidClient('Client authentication failed'),
            };
        }

        // Verify the secret using constant-time comparison
        if (!verifyClientSecret(clientSecret, clientItem.clientSecretHash)) {
            return {
                valid: false,
                error: invalidClient('Client authentication failed'),
            };
        }
    }

    return { valid: true, clientItem };
}
