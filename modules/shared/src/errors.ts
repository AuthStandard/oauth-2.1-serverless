/**
 * OAuth Server - Error Constants
 *
 * Standardized OAuth 2.1 error codes and messages.
 *
 * This file re-exports all error constants from the modular
 * errors directory for backward compatibility.
 *
 * Error codes follow the OAuth 2.1 specification exactly.
 * Human-readable descriptions are provided for debugging and logging.
 *
 * Usage:
 * ```typescript
 * import { TokenErrors, ErrorMessages } from '@oauth-server/shared';
 *
 * return error(400, TokenErrors.INVALID_GRANT, ErrorMessages.CODE_EXPIRED);
 * ```
 *
 * @see OAuth 2.1 Draft Section 3.2.4 - Error Response
 * @see OAuth 2.1 Draft Section 4.1.2.1 - Authorization Error Response
 * @see RFC 6750 Section 3 - Bearer Token Error Codes
 */

// =============================================================================
// OAuth 2.1 Error Codes
// =============================================================================

export {
    AuthorizationErrors,
    TokenErrors,
    ResourceErrors,
} from './errors/oauth-error-codes';

export type {
    AuthorizationErrorCode,
    TokenErrorCode,
    ResourceErrorCode,
    OAuthErrorCode,
} from './errors/oauth-error-codes';

// =============================================================================
// HTTP Status Codes
// =============================================================================

export { HttpStatus } from './errors/http-status';

export type { HttpStatusCode } from './errors/http-status';

// =============================================================================
// Error Messages
// =============================================================================

export { ErrorMessages } from './errors/error-messages';
