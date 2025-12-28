/**
 * OAuth Server - Request Validation Utilities
 *
 * Input validation and sanitization for OAuth 2.1 compliance.
 * Implements security best practices for parameter validation.
 *
 * This file re-exports all validation functions from the modular
 * validation directory for backward compatibility.
 *
 * Design Principles:
 * - Prevent injection attacks through strict character whitelisting
 * - Enforce RFC-compliant formats for all OAuth parameters
 * - Provide type narrowing via TypeScript type guards
 * - Fail closed: reject anything that doesn't explicitly match
 *
 * @see RFC 6749 - OAuth 2.0 Authorization Framework
 * @see RFC 7636 - Proof Key for Code Exchange (PKCE)
 * @see RFC 3986 - Uniform Resource Identifier (URI)
 * @see OAuth 2.1 Draft - https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1
 */

// =============================================================================
// OAuth Parameter Validation
// =============================================================================

export {
    isValidClientId,
    isValidRedirectUri,
    isValidState,
    isValidCodeChallenge,
    isValidCodeVerifier,
    isValidNonce,
} from './validation/oauth-params';

// =============================================================================
// Scope Validation and Utilities
// =============================================================================

export {
    isValidScope,
    isValidScopeStrict,
    parseScopes,
    validateScopeSubset,
    intersectScopes,
    joinScopes,
} from './validation/scope-utils';

// =============================================================================
// Email Validation
// =============================================================================

export {
    isValidEmail,
    normalizeEmail,
} from './validation/email';
