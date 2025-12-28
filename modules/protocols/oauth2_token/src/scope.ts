/**
 * OAuth 2.1 Token Endpoint - Scope Validation
 *
 * Implements scope validation per OAuth 2.1 Section 1.4.1.
 *
 * Scope Semantics (OAuth 2.1):
 * - Scopes are space-delimited, case-sensitive strings
 * - Order does not matter; duplicates are invalid
 * - Requested scope MUST be a subset of allowed scopes
 * - If omitted, defaults to client's full allowed scope set
 *
 * @module oauth2_token/scope
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-14#section-1.4.1
 */

import type { APIGatewayProxyResultV2 } from 'aws-lambda';
import { errorResponse } from './response';

// =============================================================================
// Types
// =============================================================================

/**
 * Result of scope validation.
 * Discriminated union ensures callers handle both success and error cases.
 */
export type ScopeValidationResult =
    | { readonly valid: true; readonly scope: string }
    | { readonly valid: false; readonly error: APIGatewayProxyResultV2 };

// =============================================================================
// Scope Validation
// =============================================================================

/**
 * Validate requested scope against client's allowed scopes.
 *
 * Per OAuth 2.1 Section 1.4.1:
 * - If scope is omitted, use client's default (all allowed scopes)
 * - Requested scopes must be a subset of allowed scopes
 * - Duplicates and empty values are rejected
 *
 * @param requestedScope - Space-delimited scope string from request
 * @param allowedScopes - Client's configured allowed scopes
 * @returns Validation result with granted scope or error response
 */
export function validateRequestedScope(
    requestedScope: string | undefined,
    allowedScopes: readonly string[]
): ScopeValidationResult {
    if (!requestedScope) {
        if (allowedScopes.length === 0) {
            return {
                valid: false,
                error: errorResponse(400, 'invalid_scope', 'No scopes configured for this client'),
            };
        }
        return { valid: true, scope: allowedScopes.join(' ') };
    }

    const scopes = requestedScope.split(' ').filter(s => s.length > 0);

    if (scopes.length === 0) {
        return {
            valid: false,
            error: errorResponse(400, 'invalid_scope', 'Invalid scope format'),
        };
    }

    const uniqueScopes = new Set(scopes);
    if (uniqueScopes.size !== scopes.length) {
        return {
            valid: false,
            error: errorResponse(400, 'invalid_scope', 'Duplicate scopes in request'),
        };
    }

    const invalidScopes = scopes.filter(s => !allowedScopes.includes(s));
    if (invalidScopes.length > 0) {
        return {
            valid: false,
            error: errorResponse(400, 'invalid_scope', `Scope not allowed: ${invalidScopes.join(', ')}`),
        };
    }

    return { valid: true, scope: scopes.join(' ') };
}

/**
 * Validate scope downscoping for refresh token grant.
 *
 * Per OAuth 2.1 Section 4.3.1:
 * - Requested scope MUST NOT include any scope not originally granted
 * - If omitted, defaults to the original grant's scope
 *
 * @param requestedScope - Space-delimited scope string from request
 * @param originalScope - Scope from the original authorization grant
 * @returns Validation result with granted scope or error response
 */
export function validateScopeDownscope(
    requestedScope: string | undefined,
    originalScope: string
): ScopeValidationResult {
    if (!requestedScope) {
        return { valid: true, scope: originalScope };
    }

    const scopes = requestedScope.split(' ').filter(s => s.length > 0);

    if (scopes.length === 0) {
        return {
            valid: false,
            error: errorResponse(400, 'invalid_scope', 'Invalid scope format'),
        };
    }

    const uniqueScopes = new Set(scopes);
    if (uniqueScopes.size !== scopes.length) {
        return {
            valid: false,
            error: errorResponse(400, 'invalid_scope', 'Duplicate scopes in request'),
        };
    }

    const originalScopes = originalScope.split(' ');
    const invalidScopes = scopes.filter(s => !originalScopes.includes(s));

    if (invalidScopes.length > 0) {
        return {
            valid: false,
            error: errorResponse(400, 'invalid_scope', 'Requested scope exceeds the scope of the original grant'),
        };
    }

    return { valid: true, scope: scopes.join(' ') };
}
