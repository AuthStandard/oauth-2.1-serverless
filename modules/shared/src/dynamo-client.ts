/**
 * OAuth Server - DynamoDB Storage Adapter
 *
 * Implements the Single Table Design pattern for all OAuth entities.
 * Uses typed interfaces from shared_types/schema.d.ts.
 *
 * Key Patterns:
 *   - Client:       PK=CLIENT#<id>       SK=CONFIG
 *   - User:         PK=USER#<sub_id>     SK=PROFILE
 *   - AuthCode:     PK=CODE#<code>       SK=METADATA
 *   - RefreshToken: PK=REFRESH#<hash>    SK=METADATA
 *   - LoginSession: PK=SESSION#<id>      SK=METADATA
 *   - SAMLProvider: PK=SAML#<issuer>     SK=CONFIG
 *
 * GSI1 Patterns (for reverse lookups):
 *   - User by Email:     GSI1PK=EMAIL#<email>     GSI1SK=USER
 *   - Codes by Client:   GSI1PK=CLIENT#<id>       GSI1SK=CODE#<timestamp>
 *   - Tokens by User:    GSI1PK=USER#<sub>        GSI1SK=REFRESH#<timestamp>
 *   - Sessions by Client: GSI1PK=CLIENT#<id>      GSI1SK=SESSION#<timestamp>
 *   - All SAML Providers: GSI1PK=SAML_PROVIDERS   GSI1SK=<issuer>
 *
 * Configuration:
 *   - TABLE_NAME: Injected via environment variable from Terraform
 *   - Region: Uses AWS SDK default (Lambda execution role region)
 *
 * Design Principles:
 *   - All configuration comes from environment variables (no hardcoded values)
 *   - Conditional updates prevent race conditions and replay attacks
 *   - TTL attributes enable automatic cleanup of expired items
 *
 * @see https://www.alexdebrie.com/posts/dynamodb-single-table/
 */

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, DeleteCommand } from '@aws-sdk/lib-dynamodb';

import type {
    ClientItem,
    UserItem,
    AuthCodeItem,
    RefreshTokenItem,
    LoginSessionItem,
    SAMLProviderItem,
} from '../../shared_types/schema';

import type { StorageAdapterConfig } from './storage/types';
import * as clientOps from './storage/client-operations';
import * as userOps from './storage/user-operations';
import * as authCodeOps from './storage/auth-code-operations';
import * as refreshTokenOps from './storage/refresh-token-operations';
import * as sessionOps from './storage/session-operations';
import * as samlOps from './storage/saml-provider-operations';

// Re-export types for backward compatibility
export type { StorageAdapterConfig } from './storage/types';

// =============================================================================
// Storage Adapter Class
// =============================================================================

/**
 * StorageAdapter provides typed access to the DynamoDB Single Table.
 * All methods enforce the correct key patterns and entity types.
 *
 * This class wraps the modular storage operations for convenience,
 * providing a single entry point for all database operations.
 */
export class StorageAdapter {
    private readonly client: DynamoDBDocumentClient;
    private readonly tableName: string;

    constructor(config: StorageAdapterConfig) {
        this.tableName = config.tableName;

        const dynamoClient = new DynamoDBClient({
            region: config.region,
        });

        this.client = DynamoDBDocumentClient.from(dynamoClient, {
            marshallOptions: {
                removeUndefinedValues: true,
                convertClassInstanceToMap: true,
            },
            unmarshallOptions: {
                wrapNumbers: false,
            },
        });
    }

    // -------------------------------------------------------------------------
    // Client Operations
    // -------------------------------------------------------------------------

    /**
     * Retrieve an OAuth client by its client_id.
     */
    async getClient(clientId: string): Promise<ClientItem | null> {
        return clientOps.getClient(this.client, this.tableName, clientId);
    }

    /**
     * Save or update an OAuth client.
     */
    async saveClient(client: ClientItem): Promise<void> {
        return clientOps.saveClient(this.client, this.tableName, client);
    }

    // -------------------------------------------------------------------------
    // User Operations
    // -------------------------------------------------------------------------

    /**
     * Retrieve a user by their subject identifier (sub).
     */
    async getUser(userId: string): Promise<UserItem | null> {
        return userOps.getUser(this.client, this.tableName, userId);
    }

    /**
     * Find a user by their email address using GSI1.
     */
    async getUserByEmail(email: string): Promise<UserItem | null> {
        return userOps.getUserByEmail(this.client, this.tableName, email);
    }

    /**
     * Save or update a user.
     */
    async saveUser(user: UserItem): Promise<void> {
        return userOps.saveUser(this.client, this.tableName, user);
    }

    // -------------------------------------------------------------------------
    // Authorization Code Operations
    // -------------------------------------------------------------------------

    /**
     * Retrieve an authorization code.
     */
    async getAuthCode(code: string): Promise<AuthCodeItem | null> {
        return authCodeOps.getAuthCode(this.client, this.tableName, code);
    }

    /**
     * Save a new authorization code.
     */
    async saveAuthCode(authCode: AuthCodeItem): Promise<void> {
        return authCodeOps.saveAuthCode(this.client, this.tableName, authCode);
    }

    /**
     * Mark an authorization code as used (consumed).
     * Uses conditional update to prevent replay attacks.
     */
    async consumeAuthCode(code: string): Promise<boolean> {
        return authCodeOps.consumeAuthCode(this.client, this.tableName, code);
    }

    // -------------------------------------------------------------------------
    // Refresh Token Operations
    // -------------------------------------------------------------------------

    /**
     * Retrieve a refresh token by its hash.
     */
    async getRefreshToken(tokenHash: string): Promise<RefreshTokenItem | null> {
        return refreshTokenOps.getRefreshToken(this.client, this.tableName, tokenHash);
    }

    /**
     * Save a new refresh token.
     */
    async saveRefreshToken(token: RefreshTokenItem): Promise<void> {
        return refreshTokenOps.saveRefreshToken(this.client, this.tableName, token);
    }

    /**
     * Mark a refresh token as rotated.
     */
    async rotateRefreshToken(tokenHash: string, replacedByHash: string): Promise<boolean> {
        return refreshTokenOps.rotateRefreshToken(
            this.client,
            this.tableName,
            tokenHash,
            replacedByHash
        );
    }

    /**
     * Revoke all refresh tokens for a user.
     */
    async revokeAllUserRefreshTokens(
        userId: string,
        reason: 'user_logout' | 'admin_action' | 'security_event'
    ): Promise<number> {
        return refreshTokenOps.revokeAllUserRefreshTokens(
            this.client,
            this.tableName,
            userId,
            reason
        );
    }

    /**
     * Revoke all tokens in a token family (for replay attack detection).
     */
    async revokeTokenFamily(familyId: string): Promise<number> {
        return refreshTokenOps.revokeTokenFamily(
            this.client,
            this.tableName,
            familyId
        );
    }

    // -------------------------------------------------------------------------
    // Login Session Operations
    // -------------------------------------------------------------------------

    /**
     * Retrieve a login session by its ID.
     */
    async getLoginSession(sessionId: string): Promise<LoginSessionItem | null> {
        return sessionOps.getLoginSession(this.client, this.tableName, sessionId);
    }

    /**
     * Save a new login session.
     */
    async saveLoginSession(session: LoginSessionItem): Promise<void> {
        return sessionOps.saveLoginSession(this.client, this.tableName, session);
    }

    /**
     * Delete a login session after it's been used.
     */
    async deleteLoginSession(sessionId: string): Promise<void> {
        return sessionOps.deleteLoginSession(this.client, this.tableName, sessionId);
    }

    /**
     * Update a login session with authentication result.
     */
    async updateLoginSessionAuth(
        sessionId: string,
        authenticatedUserId: string,
        authMethod: string
    ): Promise<boolean> {
        return sessionOps.updateLoginSessionAuth(
            this.client,
            this.tableName,
            sessionId,
            authenticatedUserId,
            authMethod
        );
    }

    /**
     * Delete expired login sessions for a specific client.
     */
    async cleanupExpiredSessions(clientId: string): Promise<number> {
        return sessionOps.cleanupExpiredSessions(this.client, this.tableName, clientId);
    }

    // -------------------------------------------------------------------------
    // SAML Provider Operations
    // -------------------------------------------------------------------------

    /**
     * Retrieve a SAML provider by its issuer (Entity ID).
     */
    async getSAMLProvider(issuer: string): Promise<SAMLProviderItem | null> {
        return samlOps.getSAMLProvider(this.client, this.tableName, issuer);
    }

    /**
     * Save or update a SAML provider configuration.
     */
    async saveSAMLProvider(provider: SAMLProviderItem): Promise<void> {
        return samlOps.saveSAMLProvider(this.client, this.tableName, provider);
    }

    /**
     * Delete a SAML provider configuration.
     */
    async deleteSAMLProvider(issuer: string): Promise<void> {
        return samlOps.deleteSAMLProvider(this.client, this.tableName, issuer);
    }

    /**
     * List all enabled SAML providers.
     */
    async listEnabledSAMLProviders(): Promise<SAMLProviderItem[]> {
        return samlOps.listEnabledSAMLProviders(this.client, this.tableName);
    }

    // -------------------------------------------------------------------------
    // Generic Operations
    // -------------------------------------------------------------------------

    /**
     * Delete an item by its keys (generic).
     */
    async deleteItem(pk: string, sk: string): Promise<void> {
        await this.client.send(
            new DeleteCommand({
                TableName: this.tableName,
                Key: { PK: pk, SK: sk },
            })
        );
    }
}

// =============================================================================
// Factory Function
// =============================================================================

/**
 * Create a StorageAdapter instance with environment configuration.
 *
 * Reads TABLE_NAME from environment variables. The AWS region is automatically
 * determined by the AWS SDK from the Lambda execution environment.
 *
 * This factory function is the recommended way to create a StorageAdapter
 * in Lambda handlers. The TABLE_NAME environment variable is injected
 * by Terraform during deployment.
 *
 * @returns Configured StorageAdapter instance
 * @throws Error if TABLE_NAME environment variable is not set
 *
 * @example
 * ```typescript
 * // In Lambda handler
 * const storage = createStorageAdapter();
 * const client = await storage.getClient(clientId);
 * ```
 */
export function createStorageAdapter(): StorageAdapter {
    const tableName = process.env.TABLE_NAME;

    if (!tableName) {
        throw new Error(
            'TABLE_NAME environment variable is required. ' +
            'Ensure the Lambda function is configured with the DynamoDB table name.'
        );
    }

    // Region is automatically determined by AWS SDK from Lambda environment
    // No need to explicitly set it - this ensures correct behavior in all regions
    return new StorageAdapter({ tableName });
}
