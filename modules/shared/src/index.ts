/**
 * OAuth Server - Shared Utilities
 *
 * Central export for all shared modules used across Lambda functions.
 *
 * Architecture:
 * - This package is a shared dependency for all protocol and strategy modules
 * - No hardcoded configuration - all values come from environment variables
 * - Follows hexagonal architecture principles with clear port definitions
 *
 * Modules:
 * - Storage Adapter: DynamoDB Single Table Design operations
 * - Audit Logger: SOC2-compliant structured JSON logging to CloudWatch
 * - Response Helpers: OAuth 2.1 compliant HTTP response formatting
 * - Validation: RFC-compliant parameter validation for OAuth 2.1
 * - Crypto: PKCE verification, token hashing, secure random generation
 * - Constants: OAuth 2.1 standard values (grant types, scopes, etc.)
 * - Errors: Standardized OAuth 2.1 error codes and messages
 * - Type Guards: Runtime type discrimination for DynamoDB entities
 *
 * @see RFC 6749 - OAuth 2.0 Authorization Framework
 * @see RFC 7636 - Proof Key for Code Exchange (PKCE)
 * @see OAuth 2.1 Draft - https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1
 */

// =============================================================================
// Storage Adapter
// =============================================================================

export {
    StorageAdapter,
    createStorageAdapter,
} from './dynamo-client';

export type { StorageAdapterConfig } from './dynamo-client';

// Re-export modular storage operations for direct use
export * as storage from './storage';

// =============================================================================
// Audit Logger
// =============================================================================

export {
    AuditLogger,
    Logger,
    withContext,
    createSystemLogger,
    createLogger,
} from './audit-logger';

export type { AuditContext, LogLevel } from './audit-logger';

// =============================================================================
// HTTP Response Helpers
// =============================================================================

export {
    // Success responses
    success,
    created,
    noContent,
    // Error responses
    error,
    invalidRequest,
    invalidClient,
    invalidGrant,
    unsupportedGrantType,
    invalidScope,
    accessDenied,
    invalidToken,
    insufficientScope,
    serverError,
    temporarilyUnavailable,
    // Redirect responses
    redirect,
    errorRedirect,
    // Form Post responses (response_mode=form_post)
    formPostResponse,
    formPostError,
    // CORS
    withCors,
    corsPreflight,
    // Token Introspection (RFC 7662)
    introspectionActive,
    introspectionInactive,
} from './response';

export type { OAuthErrorBody, IntrospectionResponse } from './response';

// =============================================================================
// Error Constants
// =============================================================================

export {
    AuthorizationErrors,
    TokenErrors,
    ResourceErrors,
    HttpStatus,
    ErrorMessages,
} from './errors';

export type {
    AuthorizationErrorCode,
    TokenErrorCode,
    ResourceErrorCode,
    OAuthErrorCode,
    HttpStatusCode,
} from './errors';

// =============================================================================
// Validation Utilities
// =============================================================================

export {
    isValidClientId,
    isValidRedirectUri,
    isValidScope,
    isValidScopeStrict,
    isValidState,
    isValidCodeChallenge,
    isValidCodeVerifier,
    isValidNonce,
    isValidEmail,
    normalizeEmail,
    parseScopes,
    validateScopeSubset,
    intersectScopes,
    joinScopes,
} from './validation';

// =============================================================================
// Cryptographic Utilities
// =============================================================================

export {
    generateCodeVerifier,
    generateCodeChallenge,
    verifyPkce,
    hashToken,
    base64UrlEncode,
    base64UrlDecode,
    generateSecureRandom,
    generateCsrfToken,
    verifyCsrfToken,
    generateTokenFamilyId,
} from './crypto';

// =============================================================================
// DPoP (Demonstrating Proof of Possession)
// =============================================================================

export {
    validateDPoPProof,
    validateDPoPProofExtended,
    calculateJwkThumbprint,
    calculateAccessTokenHash,
    generateDPoPNonce,
    buildDPoPConfirmationClaim,
    DPOP_PROOF_MAX_AGE_SECONDS,
    DPOP_MAX_CLOCK_SKEW_SECONDS,
} from './dpop';

export type {
    DPoPJwk,
    DPoPHeader,
    DPoPPayload,
    DPoPValidationResult,
    DPoPValidationResultExtended,
    DPoPValidationOptions,
} from './dpop';

// =============================================================================
// Constants
// =============================================================================

export {
    GrantTypes,
    ResponseTypes,
    ChallengeMethods,
    TokenTypes,
    ClientTypes,
    UserStatus,
    EntityTypes,
    KeyPrefixes,
    StandardScopes,
    DefaultTokenLifetimes,
    PkceConstants,
    HttpHeaders,
    JwtAlgorithm,
    AuthMethods,
} from './constants';

export type {
    GrantType,
    ResponseType,
    ChallengeMethod,
    TokenType,
    ClientType,
    UserStatusType,
    EntityType,
    AuthMethod,
} from './constants';

// =============================================================================
// Type Guards
// =============================================================================

export {
    isClientItem,
    isUserItem,
    isAuthCodeItem,
    isRefreshTokenItem,
    isSAMLProviderItem,
    isLoginSessionItem,
} from './type-guards';

// =============================================================================
// Rate Limiting
// =============================================================================

export {
    checkRateLimitInMemory,
    cleanupExpiredCounters,
    rateLimitExceeded,
    withRateLimitHeaders,
    buildRateLimitKey,
    extractClientIp,
    normalizeIpForRateLimit,
    DefaultRateLimits,
} from './rate-limit';

export type {
    RateLimitConfig,
    RateLimitResult,
    RateLimitKey,
} from './rate-limit';

// =============================================================================
// Client Authentication
// =============================================================================

export {
    authenticateClient,
    extractClientCredentials,
    verifyClientSecret,
} from './auth';

export type {
    ClientItem,
    ClientCredentials,
    ClientAuthResult,
} from './auth';


// =============================================================================
// Email Notifications (AWS SES)
// =============================================================================

export {
    Mailer,
    createMailer,
} from './mailer';

export type {
    MailerConfig,
    SendEmailParams,
    SendEmailResult,
} from './mailer';
