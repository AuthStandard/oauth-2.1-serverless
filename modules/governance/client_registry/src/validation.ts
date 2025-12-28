/**
 * RFC 7591 Client Registration Validation
 *
 * Validates client metadata per RFC 7591 Section 2.
 *
 * @see RFC 7591 Section 2 - Client Metadata
 */

import type { GrantType } from '@oauth-server/shared';
import type { ClientRegistrationRequest, ValidatedClientMetadata } from './types';

// =============================================================================
// Constants
// =============================================================================

const VALID_GRANT_TYPES: GrantType[] = [
    'authorization_code',
    'refresh_token',
    'client_credentials',
];

const VALID_RESPONSE_TYPES = ['code'];

const VALID_AUTH_METHODS = ['client_secret_basic', 'client_secret_post', 'none'] as const;

const VALID_STRATEGIES = ['PASSWORD', 'SAML', 'OIDC'];

// HTML/XSS dangerous patterns
const HTML_TAG_PATTERN = /<[^>]*>/g;
const SCRIPT_PATTERN = /<script[\s\S]*?>[\s\S]*?<\/script>/gi;
const EVENT_HANDLER_PATTERN = /\s*on\w+\s*=/gi;

// =============================================================================
// Validation Result
// =============================================================================

export interface ValidationResult {
    valid: boolean;
    error?: string;
    errorCode?: 'invalid_redirect_uri' | 'invalid_client_metadata';
    metadata?: ValidatedClientMetadata;
}

// =============================================================================
// URI Validation
// =============================================================================

/**
 * Validate a redirect URI per RFC 7591 Section 2.
 * - Must be absolute URI
 * - Must use HTTPS (except localhost for development)
 * - Must not contain fragment component
 */
function isValidRedirectUri(uri: string): boolean {
    try {
        const parsed = new URL(uri);

        // Must not have fragment
        if (parsed.hash) {
            return false;
        }

        // Must be HTTPS (allow http://localhost for development)
        const isLocalhost = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
        if (parsed.protocol !== 'https:' && !isLocalhost) {
            return false;
        }

        return true;
    } catch {
        return false;
    }
}

/**
 * Validate an optional URI field (client_uri, logo_uri, etc.).
 */
function isValidOptionalUri(uri: string | undefined): boolean {
    if (!uri) return true;
    try {
        const parsed = new URL(uri);
        return parsed.protocol === 'https:' || parsed.protocol === 'http:';
    } catch {
        return false;
    }
}

/**
 * Check if a string contains potentially dangerous HTML/script content.
 */
function containsHtmlOrScript(input: string): boolean {
    return HTML_TAG_PATTERN.test(input) || 
           SCRIPT_PATTERN.test(input) || 
           EVENT_HANDLER_PATTERN.test(input);
}

// =============================================================================
// Main Validation Function
// =============================================================================

/**
 * Validate client registration request per RFC 7591.
 *
 * @param request - The client registration request body
 * @returns Validation result with parsed metadata or error
 */
export function validateClientRegistration(request: ClientRegistrationRequest): ValidationResult {
    // Validate client_name for XSS/HTML injection
    if (request.client_name && containsHtmlOrScript(request.client_name)) {
        return {
            valid: false,
            error: 'client_name contains invalid characters (HTML/script tags not allowed)',
            errorCode: 'invalid_client_metadata',
        };
    }

    // Validate grant_types
    const grantTypes = request.grant_types || ['authorization_code'];
    for (const gt of grantTypes) {
        if (!VALID_GRANT_TYPES.includes(gt as GrantType)) {
            return {
                valid: false,
                error: `Invalid grant_type: ${gt}. Supported: ${VALID_GRANT_TYPES.join(', ')}`,
                errorCode: 'invalid_client_metadata',
            };
        }
    }

    // Validate response_types
    const responseTypes = request.response_types || ['code'];
    for (const rt of responseTypes) {
        if (!VALID_RESPONSE_TYPES.includes(rt)) {
            return {
                valid: false,
                error: `Invalid response_type: ${rt}. Supported: ${VALID_RESPONSE_TYPES.join(', ')}`,
                errorCode: 'invalid_client_metadata',
            };
        }
    }

    // redirect_uris required for authorization_code grant
    const needsRedirectUri = grantTypes.includes('authorization_code');
    const redirectUris = request.redirect_uris || [];

    if (needsRedirectUri && redirectUris.length === 0) {
        return {
            valid: false,
            error: 'redirect_uris is required for authorization_code grant',
            errorCode: 'invalid_redirect_uri',
        };
    }

    // Validate each redirect URI
    for (const uri of redirectUris) {
        if (!isValidRedirectUri(uri)) {
            return {
                valid: false,
                error: `Invalid redirect_uri: ${uri}. Must be HTTPS (or localhost) and not contain fragments.`,
                errorCode: 'invalid_redirect_uri',
            };
        }
    }

    // Validate token_endpoint_auth_method
    const authMethod = request.token_endpoint_auth_method || 'client_secret_basic';
    if (!VALID_AUTH_METHODS.includes(authMethod as typeof VALID_AUTH_METHODS[number])) {
        return {
            valid: false,
            error: `Invalid token_endpoint_auth_method: ${authMethod}`,
            errorCode: 'invalid_client_metadata',
        };
    }

    // Determine client type based on auth method
    const clientType = authMethod === 'none' ? 'PUBLIC' : 'CONFIDENTIAL';

    // Validate optional URIs
    if (!isValidOptionalUri(request.client_uri)) {
        return {
            valid: false,
            error: 'Invalid client_uri: must be a valid HTTP(S) URL',
            errorCode: 'invalid_client_metadata',
        };
    }
    if (!isValidOptionalUri(request.logo_uri)) {
        return {
            valid: false,
            error: 'Invalid logo_uri: must be a valid HTTP(S) URL',
            errorCode: 'invalid_client_metadata',
        };
    }
    if (!isValidOptionalUri(request.tos_uri)) {
        return {
            valid: false,
            error: 'Invalid tos_uri: must be a valid HTTP(S) URL',
            errorCode: 'invalid_client_metadata',
        };
    }
    if (!isValidOptionalUri(request.policy_uri)) {
        return {
            valid: false,
            error: 'Invalid policy_uri: must be a valid HTTP(S) URL',
            errorCode: 'invalid_client_metadata',
        };
    }

    // Validate enabled_strategies (custom extension)
    const enabledStrategies = request.enabled_strategies || ['PASSWORD'];
    for (const strategy of enabledStrategies) {
        if (!VALID_STRATEGIES.includes(strategy)) {
            return {
                valid: false,
                error: `Invalid strategy: ${strategy}. Supported: ${VALID_STRATEGIES.join(', ')}`,
                errorCode: 'invalid_client_metadata',
            };
        }
    }

    // Validate contacts (must be email addresses)
    if (request.contacts) {
        for (const contact of request.contacts) {
            if (!contact.includes('@')) {
                return {
                    valid: false,
                    error: `Invalid contact email: ${contact}`,
                    errorCode: 'invalid_client_metadata',
                };
            }
        }
    }

    // Build validated metadata
    const metadata: ValidatedClientMetadata = {
        clientName: request.client_name || 'Unnamed Client',
        redirectUris,
        grantTypes: grantTypes as GrantType[],
        responseTypes,
        scope: request.scope || 'openid',
        tokenEndpointAuthMethod: authMethod as 'client_secret_basic' | 'client_secret_post' | 'none',
        clientType,
        enabledStrategies,
        clientUri: request.client_uri,
        logoUri: request.logo_uri,
        tosUri: request.tos_uri,
        policyUri: request.policy_uri,
        contacts: request.contacts,
        softwareId: request.software_id,
        softwareVersion: request.software_version,
    };

    return { valid: true, metadata };
}
