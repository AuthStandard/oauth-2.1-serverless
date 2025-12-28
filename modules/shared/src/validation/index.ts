/**
 * OAuth Server - Validation Module
 *
 * Input validation and sanitization for OAuth 2.1 compliance.
 * Implements security best practices for parameter validation.
 *
 * @module validation
 */

export {
    isValidClientId,
    isValidRedirectUri,
    isValidState,
    isValidCodeChallenge,
    isValidCodeVerifier,
    isValidNonce,
} from './oauth-params';

export {
    isValidScope,
    isValidScopeStrict,
    parseScopes,
    validateScopeSubset,
    intersectScopes,
    joinScopes,
} from './scope-utils';

export {
    isValidEmail,
    normalizeEmail,
} from './email';
