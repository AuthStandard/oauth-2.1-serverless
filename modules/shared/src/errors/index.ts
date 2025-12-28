/**
 * OAuth Server - Error Constants Module
 *
 * Standardized OAuth 2.1 error codes and messages.
 *
 * @module errors
 */

export {
    AuthorizationErrors,
    TokenErrors,
    ResourceErrors,
} from './oauth-error-codes';

export type {
    AuthorizationErrorCode,
    TokenErrorCode,
    ResourceErrorCode,
    OAuthErrorCode,
} from './oauth-error-codes';

export { HttpStatus } from './http-status';

export type { HttpStatusCode } from './http-status';

export { ErrorMessages } from './error-messages';
