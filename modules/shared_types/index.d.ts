/**
 * OAuth Server - Shared Type Definitions
 *
 * Central export for all shared type definitions used across the OAuth server.
 *
 * Architecture:
 * - schema: DynamoDB entity types (Single Table Design)
 * - api: Internal API contracts (Hexagonal Architecture ports)
 * - audit: SOC2-compliant audit logging interfaces
 * - base: Foundation types for DynamoDB key patterns
 * - client: OAuth client entity types
 * - user: User profile and authentication types
 * - token: Authorization code and refresh token types
 * - session: Login session types for authorization flow
 * - saml: SAML provider configuration types
 *
 * Usage:
 * ```typescript
 * import type { ClientItem, UserItem, AuditLogger } from '@oauth-server/shared-types';
 * ```
 *
 * @see OAuth 2.1 Draft - https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1
 */

// =============================================================================
// DynamoDB Schema Types (Single Table Design)
// =============================================================================

export * from './schema';

// Re-export individual entity types for convenience
export type { LoginSessionItem } from './session';

// =============================================================================
// API Contracts (Hexagonal Architecture Ports)
// =============================================================================

export type {
    // Authentication Strategy Port
    AuthenticationStrategy,
    AuthenticatedUser,
    AuthenticationRequest,
    // Token Service Port
    TokenService,
    IssueTokenParams,
    IssuedToken,
    TokenPayload,
    // User Repository Port
    UserRepository,
    User,
    UserProfile as ApiUserProfile,
    CreateUserParams,
    UpdateUserParams,
    // Client Repository Port
    ClientRepository,
    OAuthClient,
    CreateClientParams,
    UpdateClientParams,
    // Request Context
    RequestContext,
} from './api';

// =============================================================================
// Audit Logging Types
// =============================================================================

export type {
    AuditAction,
    AuditActor,
    AuditLogEntry,
    AuditLogger,
    StrictAuditLogEntry,
    LoginDetails,
    TokenIssuedDetails,
    TokenRevokedDetails,
    TokenRefreshedDetails,
    TokenIntrospectedDetails,
    AuthSessionCreatedDetails,
    AuthCodeIssuedDetails,
    AuthCodeExchangedDetails,
    SAMLAssertionDetails,
    ClientAuthenticatedDetails,
    ClientAuthFailedDetails,
    LoginSuccessEntry,
    LoginFailureEntry,
    TokenIssuedEntry,
    TokenRevokedEntry,
    TokenRefreshedEntry,
    TokenIntrospectedEntry,
    AuthSessionCreatedEntry,
    AuthCodeIssuedEntry,
    AuthCodeExchangedEntry,
    SAMLAssertionEntry,
    ClientAuthenticatedEntry,
    ClientAuthFailedEntry,
} from './audit';
