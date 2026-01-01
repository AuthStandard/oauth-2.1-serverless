/**
 * RFC 7591/7592 Dynamic Client Registration Types
 *
 * Type definitions for OAuth 2.0 Dynamic Client Registration Protocol.
 *
 * @see RFC 7591 - OAuth 2.0 Dynamic Client Registration Protocol
 * @see RFC 7592 - OAuth 2.0 Dynamic Client Registration Management Protocol
 */

import type { GrantType } from '@oauth-server/shared';

// =============================================================================
// RFC 7591 - Client Registration Request
// =============================================================================

/**
 * Client metadata in registration request (RFC 7591 Section 2).
 */
export interface ClientRegistrationRequest {
    /** Human-readable name of the client */
    client_name?: string;
    /** Array of redirection URIs (REQUIRED for authorization_code grant) */
    redirect_uris?: string[];
    /** Array of OAuth 2.0 grant types the client will use */
    grant_types?: string[];
    /** Array of OAuth 2.0 response types the client will use */
    response_types?: string[];
    /** Space-delimited scope values the client can request */
    scope?: string;
    /** URL of the client's JSON Web Key Set document */
    jwks_uri?: string;
    /** Client's JSON Web Key Set document value */
    jwks?: object;
    /** Requested authentication method for the token endpoint */
    token_endpoint_auth_method?: 'client_secret_basic' | 'client_secret_post' | 'none';
    /** URL of the client's home page */
    client_uri?: string;
    /** URL of the client's logo image */
    logo_uri?: string;
    /** URL of the client's terms of service */
    tos_uri?: string;
    /** URL of the client's privacy policy */
    policy_uri?: string;
    /** Array of email addresses for client contacts */
    contacts?: string[];
    /** Software identifier (for software statements) */
    software_id?: string;
    /** Software version */
    software_version?: string;

    // ==========================================================================
    // Custom Extensions (Allowed by RFC 7591 Section 2)
    // ==========================================================================

    /** Authentication strategies this client can use (e.g., PASSWORD, SAML) */
    enabled_strategies?: string[];
}

// =============================================================================
// RFC 7591 - Client Registration Response
// =============================================================================

/**
 * Successful client registration response (RFC 7591 Section 3.2.1).
 */
export interface ClientRegistrationResponse {
    /** Unique client identifier issued by the authorization server */
    client_id: string;
    /** Client secret (only for confidential clients) */
    client_secret?: string;
    /** Time at which the client secret will expire (0 = never) */
    client_secret_expires_at?: number;
    /** Time at which the client identifier was issued */
    client_id_issued_at?: number;
    /** Registration access token for RFC 7592 management */
    registration_access_token?: string;
    /** URI of the client configuration endpoint (RFC 7592) */
    registration_client_uri?: string;

    // Echo back all registered metadata
    client_name?: string;
    redirect_uris?: string[];
    grant_types?: string[];
    response_types?: string[];
    scope?: string;
    token_endpoint_auth_method?: string;
    client_uri?: string;
    logo_uri?: string;
    tos_uri?: string;
    policy_uri?: string;
    contacts?: string[];
    software_id?: string;
    software_version?: string;

    // Custom extensions
    enabled_strategies?: string[];
}

// =============================================================================
// RFC 7591 - Error Response
// =============================================================================

/**
 * Client registration error codes (RFC 7591 Section 3.2.2).
 */
export type RegistrationErrorCode =
    | 'invalid_redirect_uri'
    | 'invalid_client_metadata'
    | 'invalid_software_statement'
    | 'unapproved_software_statement';

/**
 * Client registration error response.
 */
export interface RegistrationErrorResponse {
    error: RegistrationErrorCode | 'invalid_request' | 'invalid_token' | 'insufficient_scope';
    error_description?: string;
}

// =============================================================================
// RFC 7592 - Client Read Response
// =============================================================================

/**
 * Client configuration read response (RFC 7592 Section 3).
 * Same as registration response but without client_secret.
 */
export interface ClientReadResponse {
    client_id: string;
    client_id_issued_at?: number;
    registration_access_token?: string;
    registration_client_uri?: string;
    client_name?: string;
    redirect_uris?: string[];
    grant_types?: string[];
    response_types?: string[];
    scope?: string;
    token_endpoint_auth_method?: string;
    client_uri?: string;
    logo_uri?: string;
    tos_uri?: string;
    policy_uri?: string;
    contacts?: string[];
    software_id?: string;
    software_version?: string;
    enabled_strategies?: string[];
}

// =============================================================================
// Internal Types
// =============================================================================

/**
 * Environment configuration for the Lambda function.
 */
export interface EnvConfig {
    tableName: string;
    issuer: string;
    registrationEndpoint: string;
    /** Initial Access Token for open registration protection (optional) */
    initialAccessToken?: string;
    /** Whether open registration is allowed (default: false if initialAccessToken is set) */
    allowOpenRegistration?: boolean;
}

/**
 * Validated client metadata after parsing and validation.
 */
export interface ValidatedClientMetadata {
    clientName: string;
    redirectUris: string[];
    grantTypes: GrantType[];
    responseTypes: string[];
    scope: string;
    tokenEndpointAuthMethod: 'client_secret_basic' | 'client_secret_post' | 'none';
    clientType: 'PUBLIC' | 'CONFIDENTIAL';
    enabledStrategies: string[];
    clientUri?: string;
    logoUri?: string;
    tosUri?: string;
    policyUri?: string;
    contacts?: string[];
    softwareId?: string;
    softwareVersion?: string;
}
