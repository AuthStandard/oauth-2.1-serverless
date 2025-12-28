/**
 * OAuth Server - Scope Validation and Utilities
 *
 * Validation and manipulation functions for OAuth 2.1 scope parameters.
 *
 * Scope Semantics:
 * - Scopes are space-delimited, case-sensitive strings
 * - Each scope token represents a specific permission or claim set
 * - Standard OIDC scopes: openid, profile, email, offline_access
 * - Custom scopes can be defined per application requirements
 *
 * @see RFC 6749 Section 3.3 - Access Token Scope
 * @see RFC 6749 Appendix A.4 - scope ABNF
 * @see OpenID Connect Core 1.0 Section 5.4 - Requesting Claims using Scope Values
 */

// =============================================================================
// Constants
// =============================================================================

/**
 * Regex pattern for valid scope token characters.
 * Per RFC 6749 ABNF: %x21 / %x23-5B / %x5D-7E
 * (printable ASCII except space, backslash, and double-quote)
 */
const SCOPE_TOKEN_PATTERN = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

/** Maximum allowed scope string length (DoS protection) */
const MAX_SCOPE_LENGTH = 1024;

// =============================================================================
// Scope Validation
// =============================================================================

/**
 * Validate a scope parameter.
 *
 * Scopes are space-delimited, case-sensitive strings per RFC 6749 Section 3.3.
 * Each scope token must consist of printable ASCII characters except:
 * - Space (0x20) - used as delimiter
 * - Backslash (0x5C)
 * - Double-quote (0x22)
 *
 * @param scope - The scope string to validate
 * @returns True if valid
 *
 * @example
 * ```typescript
 * isValidScope('openid profile email')  // true
 * isValidScope('openid  profile')        // false (consecutive spaces)
 * isValidScope('')                       // false (empty)
 * isValidScope('   ')                    // false (whitespace only)
 * ```
 *
 * @see RFC 6749 Section 3.3 - Access Token Scope
 * @see RFC 6749 Appendix A.4 - scope ABNF
 */
export function isValidScope(scope: string | undefined | null): boolean {
    if (scope === null || scope === undefined || typeof scope !== 'string') {
        return false;
    }

    // Early length check before any processing (DoS protection)
    if (scope.length > MAX_SCOPE_LENGTH) {
        return false;
    }

    const trimmed = scope.trim();

    // Empty scope is invalid
    if (trimmed.length === 0) {
        return false;
    }

    // Check for consecutive spaces (invalid per ABNF)
    if (scope.includes('  ')) {
        return false;
    }

    // Check for leading/trailing spaces in original (indicates malformed input)
    if (scope !== trimmed) {
        return false;
    }

    const scopes = scope.split(' ');

    // Reject if any scope token is empty or contains invalid characters
    return scopes.every(s => s.length > 0 && SCOPE_TOKEN_PATTERN.test(s));
}

/**
 * Validate a scope parameter with strict duplicate checking.
 *
 * Same as isValidScope but also rejects duplicate scope tokens.
 * Use this for authorization requests where duplicates indicate
 * a malformed or potentially malicious request.
 *
 * @param scope - The scope string to validate
 * @returns True if valid and contains no duplicates
 *
 * @example
 * ```typescript
 * isValidScopeStrict('openid profile email')  // true
 * isValidScopeStrict('openid openid profile') // false (duplicate)
 * ```
 */
export function isValidScopeStrict(scope: string | undefined | null): boolean {
    if (!isValidScope(scope)) {
        return false;
    }

    const scopes = scope!.split(' ');
    const uniqueScopes = new Set(scopes);
    return uniqueScopes.size === scopes.length;
}

// =============================================================================
// Scope Utilities
// =============================================================================

/**
 * Parse a space-delimited scope string into an array.
 *
 * Handles multiple consecutive spaces gracefully by filtering empty strings.
 * Deduplicates scopes while preserving the original request order.
 *
 * @param scope - Space-delimited scope string
 * @returns Array of individual scopes (deduplicated, order preserved)
 *
 * @example
 * ```typescript
 * parseScopes('openid profile email')     // ['openid', 'profile', 'email']
 * parseScopes('openid openid profile')    // ['openid', 'profile']
 * parseScopes('openid  profile')          // ['openid', 'profile']
 * ```
 */
export function parseScopes(scope: string): string[] {
    const scopes = scope.split(' ').filter(s => s.length > 0);
    // Deduplicate while preserving order
    return [...new Set(scopes)];
}

/**
 * Check if requested scopes are a subset of allowed scopes.
 *
 * Used during authorization to ensure the client is not requesting
 * scopes beyond what it's registered for.
 *
 * @param requested - Requested scopes
 * @param allowed - Allowed scopes for the client
 * @returns True if all requested scopes are allowed
 *
 * @example
 * ```typescript
 * validateScopeSubset(['openid', 'email'], ['openid', 'profile', 'email'])  // true
 * validateScopeSubset(['openid', 'admin'], ['openid', 'profile', 'email'])  // false
 * ```
 */
export function validateScopeSubset(requested: string[], allowed: string[]): boolean {
    const allowedSet = new Set(allowed);
    return requested.every(scope => allowedSet.has(scope));
}

/**
 * Get the intersection of requested and allowed scopes.
 *
 * Used to compute the effective scope when a client requests scopes
 * that may not all be allowed. Preserves the order from the request.
 *
 * @param requested - Requested scopes
 * @param allowed - Allowed scopes
 * @returns Scopes that are both requested and allowed (preserves request order)
 *
 * @example
 * ```typescript
 * intersectScopes(['openid', 'admin', 'email'], ['openid', 'email'])  // ['openid', 'email']
 * ```
 */
export function intersectScopes(requested: string[], allowed: string[]): string[] {
    const allowedSet = new Set(allowed);
    return requested.filter(scope => allowedSet.has(scope));
}

/**
 * Join an array of scopes into a space-delimited string.
 *
 * @param scopes - Array of scope strings
 * @returns Space-delimited scope string
 *
 * @example
 * ```typescript
 * joinScopes(['openid', 'profile', 'email'])  // 'openid profile email'
 * ```
 */
export function joinScopes(scopes: string[]): string {
    return scopes.join(' ');
}
