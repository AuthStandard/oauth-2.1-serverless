/**
 * OIDC Discovery Endpoint - Lambda Handler
 *
 * Implements GET /.well-known/openid-configuration per OpenID Connect Discovery 1.0.
 * Returns OpenID Provider Metadata describing the IdP's capabilities and endpoints.
 *
 * Purpose:
 *   This endpoint enables dynamic client configuration. Clients fetch this metadata
 *   to discover authorization endpoints, token endpoints, supported scopes, and
 *   cryptographic capabilities without hardcoding these values.
 *
 * Caching Strategy:
 *   - Cache-Control: public, max-age=3600 (1 hour)
 *   - Metadata is static per deployment, safe to cache aggressively
 *   - Changes require redeployment, which invalidates Lambda cache
 *
 * Security Considerations:
 *   - No authentication required (public endpoint per OIDC Discovery spec)
 *   - CORS enabled for browser-based discovery
 *   - No sensitive data exposed (only public endpoint URLs and capabilities)
 *   - Issuer URL MUST use HTTPS per OAuth 2.1 Section 1.5
 *
 * Compliance:
 *   - OpenID Connect Discovery 1.0 Section 3 (Provider Metadata)
 *   - OAuth 2.0 Authorization Server Metadata (RFC 8414)
 *   - OAuth 2.1 Section 7.14 (Mix-up Attack Mitigation)
 *
 * Environment Variables (injected via Terraform - no hardcoded defaults):
 *   - ISSUER: OAuth 2.1 issuer URL (must be HTTPS in production)
 *
 * @module oidc_discovery
 * @see https://openid.net/specs/openid-connect-discovery-1_0.html
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-14
 * @see https://datatracker.ietf.org/doc/html/rfc8414 (OAuth 2.0 Authorization Server Metadata)
 */

import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2, Context } from 'aws-lambda';

// ============================================================================
// Shared Module Imports
// ============================================================================
// This module uses @oauth-server/shared for common utilities.
// esbuild bundles these into the final Lambda deployment package.
// See esbuild.config.mjs for bundling configuration.
// ============================================================================

import { createLogger } from '@oauth-server/shared';

// =============================================================================
// Types
// =============================================================================

/**
 * OpenID Provider Metadata per OpenID Connect Discovery 1.0 Section 3.
 * @see https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
 * @see https://datatracker.ietf.org/doc/html/rfc9449 (DPoP)
 */
interface OpenIDProviderMetadata {
    issuer: string;
    authorization_endpoint: string;
    token_endpoint: string;
    userinfo_endpoint?: string;
    jwks_uri: string;
    registration_endpoint?: string;
    scopes_supported?: string[];
    response_types_supported: string[];
    response_modes_supported?: string[];
    grant_types_supported?: string[];
    acr_values_supported?: string[];
    subject_types_supported: string[];
    id_token_signing_alg_values_supported: string[];
    id_token_encryption_alg_values_supported?: string[];
    id_token_encryption_enc_values_supported?: string[];
    userinfo_signing_alg_values_supported?: string[];
    userinfo_encryption_alg_values_supported?: string[];
    userinfo_encryption_enc_values_supported?: string[];
    request_object_signing_alg_values_supported?: string[];
    request_object_encryption_alg_values_supported?: string[];
    request_object_encryption_enc_values_supported?: string[];
    token_endpoint_auth_methods_supported?: string[];
    token_endpoint_auth_signing_alg_values_supported?: string[];
    display_values_supported?: string[];
    claim_types_supported?: string[];
    claims_supported?: string[];
    service_documentation?: string;
    claims_locales_supported?: string[];
    ui_locales_supported?: string[];
    claims_parameter_supported?: boolean;
    request_parameter_supported?: boolean;
    request_uri_parameter_supported?: boolean;
    require_request_uri_registration?: boolean;
    op_policy_uri?: string;
    op_tos_uri?: string;
    code_challenge_methods_supported?: string[];
    revocation_endpoint?: string;
    revocation_endpoint_auth_methods_supported?: string[];
    introspection_endpoint?: string;
    introspection_endpoint_auth_methods_supported?: string[];
    /** OAuth 2.1 Section 7.14 - indicates 'iss' parameter in authorization responses */
    authorization_response_iss_parameter_supported?: boolean;
    /** OIDC RP-Initiated Logout 1.0 - end session endpoint */
    end_session_endpoint?: string;
    /** RFC 9449 - DPoP signing algorithms supported */
    dpop_signing_alg_values_supported?: string[];
}

// =============================================================================
// Environment Configuration
// =============================================================================

interface EnvConfig {
    issuer: string;
}

function getEnvConfig(): EnvConfig {
    const issuer = process.env.ISSUER;

    if (!issuer) {
        throw new Error('ISSUER environment variable is required');
    }

    return { issuer };
}

// =============================================================================
// Response Helpers
// =============================================================================

/**
 * SOC2-compliant security headers applied to all responses.
 */
const SECURITY_HEADERS = {
    'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
    'Referrer-Policy': 'strict-origin-when-cross-origin',
} as const;

const JSON_HEADERS = {
    'Content-Type': 'application/json',
    'Cache-Control': 'public, max-age=3600',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    ...SECURITY_HEADERS,
} as const;

function success<T>(body: T): APIGatewayProxyResultV2 {
    return {
        statusCode: 200,
        headers: JSON_HEADERS,
        body: JSON.stringify(body),
    };
}

function serverError(description: string): APIGatewayProxyResultV2 {
    return {
        statusCode: 500,
        headers: {
            'Content-Type': 'application/json',
            ...SECURITY_HEADERS,
        },
        body: JSON.stringify({ error: 'server_error', error_description: description }),
    };
}

// =============================================================================
// Lambda Handler
// =============================================================================

export const handler = async (
    event: APIGatewayProxyEventV2,
    context: Context
): Promise<APIGatewayProxyResultV2> => {
    const logger = createLogger(event, context);

    try {
        logger.info('OIDC Discovery request received', { path: event.requestContext.http.path });

        const config = getEnvConfig();
        const issuer = config.issuer;

        // Build OpenID Provider Metadata per OIDC Discovery 1.0 and OAuth 2.1
        const metadata: OpenIDProviderMetadata = {
            // =================================================================
            // REQUIRED Fields per OIDC Discovery 1.0 Section 3
            // =================================================================

            // Issuer Identifier (must exactly match 'iss' claim in tokens)
            issuer,

            // Authorization endpoint per OAuth 2.1 Section 3.1
            authorization_endpoint: `${issuer}/authorize`,

            // Token endpoint per OAuth 2.1 Section 3.2
            token_endpoint: `${issuer}/token`,

            // JWKS URI for token verification per RFC 7517
            jwks_uri: `${issuer}/keys`,

            // RFC 7591 Dynamic Client Registration endpoint
            registration_endpoint: `${issuer}/connect/register`,

            // Response types (OAuth 2.1 mandates 'code' only - implicit removed)
            response_types_supported: ['code'],

            // Subject identifier types per OIDC Core Section 8
            subject_types_supported: ['public'],

            // ID Token signing algorithms per OIDC Core Section 15.1
            id_token_signing_alg_values_supported: ['RS256'],

            // =================================================================
            // RECOMMENDED Fields
            // =================================================================

            // Response modes supported per OAuth 2.0 Multiple Response Types
            // and OAuth 2.0 Form Post Response Mode
            response_modes_supported: ['query', 'fragment', 'form_post'],

            // Grant types supported per OAuth 2.1
            grant_types_supported: [
                'authorization_code',
                'refresh_token',
                'client_credentials',
            ],

            // Token endpoint authentication methods per OAuth 2.1 Section 2.4
            token_endpoint_auth_methods_supported: [
                'client_secret_basic',
                'client_secret_post',
                'none', // For public clients
            ],

            // Scopes supported per OIDC Core Section 5.4
            scopes_supported: [
                'openid',
                'profile',
                'email',
                'offline_access',
            ],

            // Claims supported in ID Token and UserInfo per OIDC Core Section 5.1
            // Also includes RFC 9068 claims for JWT access tokens
            claims_supported: [
                // Standard JWT claims
                'sub',
                'iss',
                'aud',
                'exp',
                'iat',
                'nbf',
                'jti',
                // OIDC Core claims
                'auth_time',
                'nonce',
                'at_hash',
                // OAuth 2.1 / RFC 9068 claims
                'client_id',
                'scope',
                // Profile scope claims
                'name',
                'given_name',
                'family_name',
                'picture',
                'locale',
                'zoneinfo',
                // Email scope claims
                'email',
                'email_verified',
            ],

            // PKCE support per OAuth 2.1 Section 4.1.1 (S256 mandatory, plain removed)
            code_challenge_methods_supported: ['S256'],

            // =================================================================
            // OIDC UserInfo Endpoint (OIDC Core Section 5.3)
            // =================================================================

            // UserInfo endpoint for retrieving user claims
            userinfo_endpoint: `${issuer}/userinfo`,

            // =================================================================
            // Token Revocation (RFC 7009)
            // =================================================================

            // Revocation endpoint for invalidating tokens
            revocation_endpoint: `${issuer}/revoke`,

            // Authentication methods supported at revocation endpoint
            revocation_endpoint_auth_methods_supported: [
                'client_secret_basic',
                'client_secret_post',
                'none',
            ],

            // =================================================================
            // Token Introspection (RFC 7662)
            // =================================================================

            // Introspection endpoint for validating tokens
            introspection_endpoint: `${issuer}/introspect`,

            // Authentication methods supported at introspection endpoint
            introspection_endpoint_auth_methods_supported: [
                'client_secret_basic',
                'client_secret_post',
            ],

            // =================================================================
            // OAuth 2.1 Mix-Up Attack Mitigation (Section 7.14)
            // =================================================================

            // Indicates that the authorization server includes the 'iss' parameter
            // in authorization responses per OAuth 2.1 Section 7.14
            authorization_response_iss_parameter_supported: true,

            // =================================================================
            // OIDC RP-Initiated Logout (OIDC RP-Initiated Logout 1.0)
            // =================================================================

            // End session endpoint for RP-initiated logout
            // @see https://openid.net/specs/openid-connect-rpinitiated-1_0.html
            end_session_endpoint: `${issuer}/connect/logout`,

            // =================================================================
            // DPoP Support (RFC 9449)
            // =================================================================

            // DPoP signing algorithms supported for sender-constrained tokens
            // @see https://datatracker.ietf.org/doc/html/rfc9449
            dpop_signing_alg_values_supported: [
                'RS256',
                'RS384',
                'RS512',
                'ES256',
                'ES384',
                'ES512',
                'PS256',
                'PS384',
                'PS512',
            ],

            // =================================================================
            // OPTIONAL Fields - Explicitly Disabled
            // =================================================================

            // Claims parameter not supported (simplifies implementation)
            claims_parameter_supported: false,

            // Request object not supported (simplifies implementation)
            request_parameter_supported: false,

            // Request URI not supported (security consideration - prevents SSRF)
            request_uri_parameter_supported: false,
        };

        logger.info('Returning OIDC metadata', { issuer });

        return success(metadata);
    } catch (err) {
        const error = err as Error;
        logger.error('OIDC Discovery error', { error: error.message, stack: error.stack });
        return serverError('An unexpected error occurred');
    }
};
