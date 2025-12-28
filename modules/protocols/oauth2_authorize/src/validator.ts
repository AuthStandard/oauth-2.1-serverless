/**
 * OAuth 2.1 Authorization Request Validator
 *
 * Validates authorization requests per OAuth 2.1 (draft-ietf-oauth-v2-1-14).
 *
 * Security:
 * - Mandatory PKCE with S256 only (plain method removed)
 * - Strict parameter validation prevents injection attacks
 * - Duplicate parameter rejection per OAuth 2.1 Section 3.1
 * - Validation order per Section 4.1.2.1 (redirect_uri errors shown, not redirected)
 *
 * @module oauth2_authorize/validator
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-14#section-4.1.1
 * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
 */

import type { APIGatewayProxyResultV2, APIGatewayProxyEventV2 } from 'aws-lambda';
import {
    invalidRequest,
    isValidClientId,
    isValidRedirectUri,
    isValidScope,
    isValidState,
    isValidCodeChallenge,
    isValidNonce,
} from '@oauth-server/shared';
import type { AuthorizeParams, ResponseMode, PromptValue } from './types';

// =============================================================================
// Constants
// =============================================================================

/** Maximum login_hint length (prevents DoS) */
const MAX_LOGIN_HINT_LENGTH = 256;

/** Maximum ui_locales length */
const MAX_UI_LOCALES_LENGTH = 128;

/** Maximum acr_values length */
const MAX_ACR_VALUES_LENGTH = 512;

/** Valid response_mode values */
const VALID_RESPONSE_MODES: readonly ResponseMode[] = ['query', 'fragment', 'form_post'];

/** Valid prompt values */
const VALID_PROMPT_VALUES: readonly PromptValue[] = ['none', 'login', 'consent', 'select_account'];

// =============================================================================
// Types
// =============================================================================

export type ValidationResult =
    | { readonly valid: true; readonly params: AuthorizeParams }
    | { readonly valid: false; readonly error: APIGatewayProxyResultV2 };

// =============================================================================
// Duplicate Parameter Detection
// =============================================================================

/**
 * Check for duplicate parameters in the query string.
 *
 * Per OAuth 2.1 Section 3.1, request parameters MUST NOT be included
 * more than once. This prevents parameter pollution attacks.
 *
 * @param event - API Gateway HTTP API v2 event with raw query string
 * @returns Array of duplicate parameter names, empty if none
 */
export function findDuplicateParams(event: APIGatewayProxyEventV2): string[] {
    // HTTP API v2 uses rawQueryString - parse it to detect duplicates
    const rawQueryString = event.rawQueryString || '';
    if (!rawQueryString) {
        return [];
    }

    const paramCounts = new Map<string, number>();
    const pairs = rawQueryString.split('&');

    for (const pair of pairs) {
        const [key] = pair.split('=');
        if (key) {
            const decodedKey = decodeURIComponent(key);
            paramCounts.set(decodedKey, (paramCounts.get(decodedKey) || 0) + 1);
        }
    }

    const duplicates: string[] = [];
    for (const [key, count] of paramCounts) {
        if (count > 1) {
            duplicates.push(key);
        }
    }

    return duplicates;
}

// =============================================================================
// Parameter Validation Helpers
// =============================================================================

/**
 * Validate response_mode parameter.
 *
 * @param responseMode - The response_mode value
 * @returns True if valid or undefined
 */
function isValidResponseMode(responseMode: string | undefined): responseMode is ResponseMode | undefined {
    if (responseMode === undefined) {
        return true;
    }
    return VALID_RESPONSE_MODES.includes(responseMode as ResponseMode);
}

/**
 * Validate prompt parameter.
 *
 * Per OIDC Core 1.0, prompt can be a space-delimited list of values.
 * However, 'none' MUST NOT be combined with other values.
 *
 * @param prompt - The prompt value
 * @returns True if valid or undefined
 */
function isValidPrompt(prompt: string | undefined): boolean {
    if (prompt === undefined) {
        return true;
    }

    const values = prompt.split(' ').filter(v => v.length > 0);
    if (values.length === 0) {
        return false;
    }

    // Check all values are valid
    for (const value of values) {
        if (!VALID_PROMPT_VALUES.includes(value as PromptValue)) {
            return false;
        }
    }

    // 'none' cannot be combined with other values
    if (values.includes('none') && values.length > 1) {
        return false;
    }

    return true;
}

/**
 * Validate login_hint parameter.
 *
 * @param loginHint - The login_hint value
 * @returns True if valid or undefined
 */
function isValidLoginHint(loginHint: string | undefined): boolean {
    if (loginHint === undefined) {
        return true;
    }
    return loginHint.length > 0 && loginHint.length <= MAX_LOGIN_HINT_LENGTH;
}

/**
 * Validate max_age parameter.
 *
 * @param maxAge - The max_age value as string
 * @returns Parsed number or undefined, null if invalid
 */
function parseMaxAge(maxAge: string | undefined): number | undefined | null {
    if (maxAge === undefined) {
        return undefined;
    }
    const parsed = parseInt(maxAge, 10);
    if (isNaN(parsed) || parsed < 0 || !Number.isInteger(parsed)) {
        return null; // Invalid
    }
    return parsed;
}

/**
 * Validate ui_locales parameter.
 *
 * @param uiLocales - Space-delimited BCP47 language tags
 * @returns True if valid or undefined
 */
function isValidUiLocales(uiLocales: string | undefined): boolean {
    if (uiLocales === undefined) {
        return true;
    }
    return uiLocales.length > 0 && uiLocales.length <= MAX_UI_LOCALES_LENGTH;
}

/**
 * Validate acr_values parameter.
 *
 * @param acrValues - Space-delimited ACR values
 * @returns True if valid or undefined
 */
function isValidAcrValues(acrValues: string | undefined): boolean {
    if (acrValues === undefined) {
        return true;
    }
    return acrValues.length > 0 && acrValues.length <= MAX_ACR_VALUES_LENGTH;
}

// =============================================================================
// Main Validation
// =============================================================================

/**
 * Raw authorization parameters from query string.
 */
interface RawAuthorizeParams {
    clientId?: string;
    responseType?: string;
    redirectUri?: string;
    scope?: string;
    state?: string;
    codeChallenge?: string;
    codeChallengeMethod?: string;
    nonce?: string;
    responseMode?: string;
    prompt?: string;
    loginHint?: string;
    maxAge?: string;
    uiLocales?: string;
    acrValues?: string;
}

/**
 * Validate authorization request parameters.
 *
 * Validates all OAuth 2.1 and OIDC authorization request parameters.
 * Returns either validated params or an error response.
 *
 * @param params - Raw parameters from query string
 * @param event - Optional API Gateway event for duplicate detection
 * @returns Validation result with params or error
 */
export function validateAuthorizationParams(
    params: RawAuthorizeParams,
    event?: APIGatewayProxyEventV2
): ValidationResult {
    // Check for duplicate parameters (OAuth 2.1 Section 3.1)
    if (event) {
        const duplicates = findDuplicateParams(event);
        if (duplicates.length > 0) {
            return {
                valid: false,
                error: invalidRequest(`Duplicate parameters not allowed: ${duplicates.join(', ')}`),
            };
        }
    }

    // client_id: REQUIRED
    if (!params.clientId) {
        return { valid: false, error: invalidRequest('Missing required parameter: client_id') };
    }

    if (!isValidClientId(params.clientId)) {
        return { valid: false, error: invalidRequest('Invalid client_id format') };
    }

    // response_type: REQUIRED, must be 'code'
    if (!params.responseType) {
        return { valid: false, error: invalidRequest('Missing required parameter: response_type') };
    }

    if (params.responseType !== 'code') {
        return { valid: false, error: invalidRequest('response_type must be "code" (OAuth 2.1)') };
    }

    // redirect_uri: REQUIRED
    if (!params.redirectUri) {
        return { valid: false, error: invalidRequest('Missing required parameter: redirect_uri') };
    }

    if (!isValidRedirectUri(params.redirectUri)) {
        return { valid: false, error: invalidRequest('Invalid redirect_uri format') };
    }

    // code_challenge: REQUIRED (PKCE mandatory in OAuth 2.1)
    if (!params.codeChallenge) {
        return { valid: false, error: invalidRequest('Missing required parameter: code_challenge (PKCE is mandatory in OAuth 2.1)') };
    }

    if (!isValidCodeChallenge(params.codeChallenge)) {
        return { valid: false, error: invalidRequest('Invalid code_challenge format') };
    }

    // code_challenge_method: must be S256 (plain deprecated)
    if (params.codeChallengeMethod && params.codeChallengeMethod !== 'S256') {
        return { valid: false, error: invalidRequest('code_challenge_method must be "S256" (OAuth 2.1)') };
    }

    // scope: OPTIONAL
    if (params.scope && !isValidScope(params.scope)) {
        return { valid: false, error: invalidRequest('Invalid scope format or duplicate scopes') };
    }

    // state: RECOMMENDED
    if (params.state && !isValidState(params.state)) {
        return { valid: false, error: invalidRequest('Invalid state parameter') };
    }

    // nonce: OPTIONAL (OIDC)
    if (params.nonce && !isValidNonce(params.nonce)) {
        return { valid: false, error: invalidRequest('Invalid nonce parameter') };
    }

    // response_mode: OPTIONAL
    if (!isValidResponseMode(params.responseMode)) {
        return { valid: false, error: invalidRequest('Invalid response_mode. Supported values: query, fragment, form_post') };
    }

    // prompt: OPTIONAL
    if (!isValidPrompt(params.prompt)) {
        return { valid: false, error: invalidRequest('Invalid prompt parameter. Supported values: none, login, consent, select_account') };
    }

    // login_hint: OPTIONAL
    if (!isValidLoginHint(params.loginHint)) {
        return { valid: false, error: invalidRequest('Invalid login_hint parameter') };
    }

    // max_age: OPTIONAL
    const maxAge = parseMaxAge(params.maxAge as string | undefined);
    if (maxAge === null) {
        return { valid: false, error: invalidRequest('Invalid max_age parameter. Must be a non-negative integer') };
    }

    // ui_locales: OPTIONAL
    if (!isValidUiLocales(params.uiLocales)) {
        return { valid: false, error: invalidRequest('Invalid ui_locales parameter') };
    }

    // acr_values: OPTIONAL
    if (!isValidAcrValues(params.acrValues)) {
        return { valid: false, error: invalidRequest('Invalid acr_values parameter') };
    }

    return {
        valid: true,
        params: {
            clientId: params.clientId as string,
            responseType: 'code' as const,
            redirectUri: params.redirectUri as string,
            scope: (params.scope as string) || 'openid',
            state: params.state as string | undefined,
            codeChallenge: params.codeChallenge as string,
            codeChallengeMethod: 'S256' as const,
            nonce: params.nonce as string | undefined,
            responseMode: params.responseMode as ResponseMode | undefined,
            prompt: params.prompt as PromptValue | undefined,
            loginHint: params.loginHint as string | undefined,
            maxAge: maxAge,
            uiLocales: params.uiLocales as string | undefined,
            acrValues: params.acrValues as string | undefined,
        },
    };
}
