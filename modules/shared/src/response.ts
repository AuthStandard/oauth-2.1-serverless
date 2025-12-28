/**
 * OAuth Server - Standardized HTTP Response Helpers
 *
 * Provides consistent response formatting for all Lambda functions.
 * All responses follow OAuth 2.1 specification requirements and SOC2 compliance.
 *
 * Key Requirements:
 * - Token responses MUST include Cache-Control: no-store (RFC 6749 Section 5.1)
 * - Error responses MUST use application/json content type
 * - Redirects use 303 See Other for POST-redirect-GET pattern
 * - All responses include SOC2-compliant security headers
 *
 * Security Headers (SOC2 Compliance):
 * - Strict-Transport-Security: Enforces HTTPS connections (HSTS)
 * - X-Content-Type-Options: nosniff - Prevents MIME type sniffing
 * - X-Frame-Options: DENY - Prevents clickjacking
 * - Content-Security-Policy: Restricts resource loading
 * - Cache-Control: no-store - Prevents caching of sensitive responses
 * - Pragma: no-cache - HTTP/1.0 backward compatibility
 *
 * Note: HTTP API Gateway v2 does not support response header manipulation
 * at the gateway level. Security headers are added at the Lambda response
 * level for consistent enforcement across all endpoints.
 *
 * @see OAuth 2.1 Draft Section 3.2.3 - Successful Response
 * @see OAuth 2.1 Draft Section 3.2.4 - Error Response
 * @see RFC 6749 Section 5.1 - Successful Response (Cache-Control requirement)
 * @see RFC 6797 - HTTP Strict Transport Security (HSTS)
 */

import type { APIGatewayProxyResultV2 } from 'aws-lambda';

// =============================================================================
// Types
// =============================================================================

/**
 * Structured API Gateway response (excludes string shorthand).
 * Used for functions that need to manipulate response headers.
 */
type StructuredResponse = Exclude<APIGatewayProxyResultV2, string>;

// =============================================================================
// Response Headers
// =============================================================================

/**
 * SOC2-compliant security headers applied to all responses.
 *
 * - Strict-Transport-Security: 2 years with includeSubDomains and preload
 *   Enforces HTTPS for all future requests (RFC 6797)
 * - X-Content-Type-Options: nosniff
 *   Prevents browsers from MIME-sniffing responses
 * - X-Frame-Options: DENY
 *   Prevents clickjacking by blocking iframe embedding
 * - Referrer-Policy: strict-origin-when-cross-origin
 *   Limits referrer information leakage
 */
const SECURITY_HEADERS = {
    'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
} as const;

/**
 * Standard headers for JSON API responses.
 * Includes mandatory OAuth 2.1 cache control headers and SOC2 security headers.
 */
const JSON_HEADERS = {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
    ...SECURITY_HEADERS,
} as const;

/**
 * Headers for redirect responses.
 * Cache control prevents caching of redirect URLs.
 * Security headers protect against MITM and clickjacking.
 */
const REDIRECT_HEADERS = {
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
    ...SECURITY_HEADERS,
} as const;

// =============================================================================
// Success Responses
// =============================================================================

/**
 * Return a successful JSON response.
 *
 * @param body - Response body (will be JSON stringified)
 * @param statusCode - HTTP status code (default: 200)
 * @returns APIGatewayProxyResultV2
 *
 * @example
 * ```typescript
 * return success({ access_token: 'xxx', token_type: 'Bearer' });
 * ```
 */
export function success<T>(body: T, statusCode = 200): APIGatewayProxyResultV2 {
    return {
        statusCode,
        headers: JSON_HEADERS,
        body: JSON.stringify(body),
    };
}

/**
 * Return a 201 Created response.
 */
export function created<T>(body: T): APIGatewayProxyResultV2 {
    return success(body, 201);
}

/**
 * Return a 204 No Content response.
 * Includes security headers for SOC2 compliance.
 */
export function noContent(): APIGatewayProxyResultV2 {
    return {
        statusCode: 204,
        headers: {
            'Cache-Control': 'no-store',
            ...SECURITY_HEADERS,
        },
        body: '',
    };
}

// =============================================================================
// Error Responses (OAuth 2.1 Compliant)
// =============================================================================

/**
 * OAuth 2.1 error response body format.
 */
export interface OAuthErrorBody {
    error: string;
    error_description?: string;
    error_uri?: string;
}

/**
 * Return an error response.
 *
 * @param statusCode - HTTP status code
 * @param error - OAuth error code (e.g., 'invalid_request')
 * @param description - Human-readable error description
 * @returns APIGatewayProxyResultV2
 *
 * @example
 * ```typescript
 * return error(400, 'invalid_request', 'Missing required parameter: client_id');
 * ```
 */
export function error(
    statusCode: number,
    errorCode: string,
    description?: string
): APIGatewayProxyResultV2 {
    const body: OAuthErrorBody = {
        error: errorCode,
    };

    if (description) {
        body.error_description = description;
    }

    return {
        statusCode,
        headers: JSON_HEADERS,
        body: JSON.stringify(body),
    };
}

// ---------------------------------------------------------------------------
// Common OAuth 2.1 Errors
// ---------------------------------------------------------------------------

/**
 * 400 Bad Request - Invalid request parameters.
 */
export function invalidRequest(description: string): APIGatewayProxyResultV2 {
    return error(400, 'invalid_request', description);
}

/**
 * 401 Unauthorized - Invalid client credentials.
 */
export function invalidClient(description?: string): APIGatewayProxyResultV2 {
    return error(401, 'invalid_client', description || 'Client authentication failed');
}

/**
 * 400 Bad Request - Invalid authorization grant.
 */
export function invalidGrant(description?: string): APIGatewayProxyResultV2 {
    return error(400, 'invalid_grant', description || 'The provided authorization grant is invalid');
}

/**
 * 400 Bad Request - Unsupported grant type.
 */
export function unsupportedGrantType(): APIGatewayProxyResultV2 {
    return error(400, 'unsupported_grant_type', 'The authorization grant type is not supported');
}

/**
 * 400 Bad Request - Invalid scope requested.
 */
export function invalidScope(description?: string): APIGatewayProxyResultV2 {
    return error(400, 'invalid_scope', description || 'The requested scope is invalid or unknown');
}

/**
 * 403 Forbidden - Access denied by resource owner or authorization server.
 */
export function accessDenied(description?: string): APIGatewayProxyResultV2 {
    return error(403, 'access_denied', description || 'The resource owner or authorization server denied the request');
}

/**
 * 401 Unauthorized - Invalid or expired access token.
 */
export function invalidToken(description?: string): APIGatewayProxyResultV2 {
    return error(401, 'invalid_token', description || 'The access token is invalid or expired');
}

/**
 * 403 Forbidden - Insufficient scope for the request.
 */
export function insufficientScope(requiredScope?: string): APIGatewayProxyResultV2 {
    const description = requiredScope
        ? `This request requires the '${requiredScope}' scope`
        : 'The request requires higher privileges than provided';
    return error(403, 'insufficient_scope', description);
}

/**
 * 500 Internal Server Error.
 */
export function serverError(description?: string): APIGatewayProxyResultV2 {
    return error(500, 'server_error', description || 'An unexpected error occurred');
}

/**
 * 503 Service Unavailable - Server temporarily unable to handle request.
 */
export function temporarilyUnavailable(description?: string): APIGatewayProxyResultV2 {
    return error(503, 'temporarily_unavailable', description || 'The server is temporarily unable to handle the request');
}

// =============================================================================
// Redirect Responses
// =============================================================================

/**
 * Return an HTTP 303 See Other redirect response.
 * Used after successful authorization to redirect back to the client.
 *
 * @param url - The redirect URL (including query parameters)
 * @returns APIGatewayProxyResultV2
 *
 * @example
 * ```typescript
 * return redirect('https://client.example.com/callback?code=xyz&state=abc');
 * ```
 */
export function redirect(url: string): APIGatewayProxyResultV2 {
    return {
        statusCode: 303,
        headers: {
            ...REDIRECT_HEADERS,
            Location: url,
        },
        body: '',
    };
}

/**
 * Return an error redirect (OAuth authorization endpoint errors).
 * Appends error parameters to the redirect URI.
 *
 * @param redirectUri - Client's redirect URI
 * @param errorCode - OAuth error code
 * @param description - Error description
 * @param state - State parameter to include (if provided by client)
 * @returns APIGatewayProxyResultV2
 */
export function errorRedirect(
    redirectUri: string,
    errorCode: string,
    description: string,
    state?: string
): APIGatewayProxyResultV2 {
    const url = new URL(redirectUri);
    url.searchParams.set('error', errorCode);
    url.searchParams.set('error_description', description);

    if (state) {
        url.searchParams.set('state', state);
    }

    return redirect(url.toString());
}

// =============================================================================
// Form Post Response (response_mode=form_post)
// =============================================================================

/**
 * Headers for HTML form post responses.
 * Includes security headers to prevent clickjacking and XSS.
 * CSP is relaxed to allow inline scripts for auto-submit functionality.
 */
const HTML_HEADERS = {
    'Content-Type': 'text/html;charset=UTF-8',
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
    ...SECURITY_HEADERS,
    'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'",
} as const;

/**
 * Escape HTML special characters to prevent XSS.
 *
 * @param str - String to escape
 * @returns HTML-escaped string
 */
function escapeHtml(str: string): string {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}

/**
 * Generate hidden input fields HTML from parameters.
 * All values are HTML-escaped to prevent XSS.
 */
function generateHiddenFields(params: Record<string, string>): string {
    return Object.entries(params)
        .map(([name, value]) => `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}"/>`)
        .join('\n      ');
}

/**
 * Default form_post HTML template.
 * Used when no custom template is provided.
 */
const DEFAULT_FORM_POST_TEMPLATE = `<!DOCTYPE html>
<html lang="en">
  <head>
    <title>Authorization Response</title>
  </head>
  <body onload="document.forms[0].submit()">
    <noscript>
      <p>JavaScript is required. Please click the button below to continue.</p>
    </noscript>
    <form method="POST" action="{{REDIRECT_URI}}">
      {{HIDDEN_FIELDS}}
      <noscript>
        <button type="submit">Continue</button>
      </noscript>
    </form>
  </body>
</html>`;

/**
 * Return a form_post response per OAuth 2.0 Form Post Response Mode.
 *
 * This response mode sends the authorization response parameters via
 * an HTML form that auto-submits via POST to the redirect URI.
 * Useful for SPAs and scenarios where fragment-based responses are problematic.
 *
 * Security:
 * - All parameter values are HTML-escaped to prevent XSS
 * - X-Frame-Options: DENY prevents clickjacking
 * - CSP restricts script execution to inline only (for auto-submit)
 * - Cache-Control: no-store prevents caching of sensitive data
 *
 * @param redirectUri - Client's redirect URI (form action)
 * @param params - Parameters to include in the form (code, state, iss, etc.)
 * @param template - Optional custom HTML template with {{REDIRECT_URI}} and {{HIDDEN_FIELDS}} placeholders
 * @returns APIGatewayProxyResultV2 with HTML body
 *
 * @see https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
 */
export function formPostResponse(
    redirectUri: string,
    params: Record<string, string>,
    template?: string
): APIGatewayProxyResultV2 {
    const escapedUri = escapeHtml(redirectUri);
    const hiddenInputs = generateHiddenFields(params);

    const html = (template || DEFAULT_FORM_POST_TEMPLATE)
        .replace(/\{\{REDIRECT_URI\}\}/g, escapedUri)
        .replace(/\{\{HIDDEN_FIELDS\}\}/g, hiddenInputs);

    return {
        statusCode: 200,
        headers: HTML_HEADERS,
        body: html,
    };
}

/**
 * Return a form_post error response.
 *
 * @param redirectUri - Client's redirect URI
 * @param errorCode - OAuth error code
 * @param description - Error description
 * @param state - State parameter (if provided)
 * @param issuer - Issuer identifier (for mix-up mitigation)
 * @returns APIGatewayProxyResultV2 with HTML form
 */
export function formPostError(
    redirectUri: string,
    errorCode: string,
    description: string,
    state?: string,
    issuer?: string
): APIGatewayProxyResultV2 {
    const params: Record<string, string> = {
        error: errorCode,
        error_description: description,
    };

    if (state) {
        params.state = state;
    }

    if (issuer) {
        params.iss = issuer;
    }

    return formPostResponse(redirectUri, params);
}

// =============================================================================
// CORS Support
// =============================================================================

/**
 * Add CORS headers to a response.
 * Preserves existing security headers while adding CORS headers.
 *
 * @param response - The response to add CORS headers to
 * @param origin - The allowed origin (default: '*')
 * @returns APIGatewayProxyResultV2 with CORS headers
 */
export function withCors(
    response: StructuredResponse,
    origin = '*'
): StructuredResponse {
    return {
        ...response,
        headers: {
            ...SECURITY_HEADERS,
            ...response.headers,
            'Access-Control-Allow-Origin': origin,
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        },
    };
}

/**
 * Return a CORS preflight response.
 *
 * Handles OPTIONS requests for CORS preflight checks.
 * The Access-Control-Max-Age header caches the preflight response
 * for 24 hours (86400 seconds) to reduce preflight requests.
 * Includes SOC2-compliant security headers.
 *
 * @param origin - The allowed origin (default: '*')
 * @returns APIGatewayProxyResultV2 with CORS headers
 */
export function corsPreflight(origin = '*'): APIGatewayProxyResultV2 {
    return {
        statusCode: 204,
        headers: {
            ...SECURITY_HEADERS,
            'Access-Control-Allow-Origin': origin,
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            'Access-Control-Max-Age': '86400',
        },
        body: '',
    };
}

// =============================================================================
// Token Introspection Response (RFC 7662)
// =============================================================================

/**
 * Token introspection response for an active token.
 *
 * @see RFC 7662 Section 2.2 - Introspection Response
 * @see RFC 9449 Section 9 - Token Introspection
 */
export interface IntrospectionResponse {
    active: true;
    scope?: string;
    client_id?: string;
    username?: string;
    token_type?: string;
    exp?: number;
    iat?: number;
    nbf?: number;
    sub?: string;
    aud?: string | string[];
    iss?: string;
    jti?: string;
    /** DPoP confirmation claim for sender-constrained tokens (RFC 9449) */
    cnf?: { jkt: string };
}

/**
 * Return a token introspection response for an active token.
 *
 * @param claims - Token claims to include in the response
 * @returns APIGatewayProxyResultV2 with introspection response
 *
 * @see RFC 7662 Section 2.2 - Introspection Response
 */
export function introspectionActive(claims: Omit<IntrospectionResponse, 'active'>): APIGatewayProxyResultV2 {
    return success({
        active: true,
        ...claims,
    });
}

/**
 * Return a token introspection response for an inactive token.
 *
 * Per RFC 7662, the only required field for inactive tokens is "active": false.
 * No additional information should be returned to prevent information leakage.
 *
 * @returns APIGatewayProxyResultV2 with { active: false }
 *
 * @see RFC 7662 Section 2.2 - Introspection Response
 */
export function introspectionInactive(): APIGatewayProxyResultV2 {
    return success({ active: false });
}
