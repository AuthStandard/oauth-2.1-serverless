/**
 * OIDC RP-Initiated Logout - Response Helpers
 *
 * HTTP response builders for the logout endpoint.
 * Includes redirect responses and logout confirmation pages.
 *
 * @see https://openid.net/specs/openid-connect-rpinitiated-1_0.html
 */

import type { APIGatewayProxyResultV2 } from 'aws-lambda';

// =============================================================================
// Response Headers
// =============================================================================

/**
 * SOC2-compliant security headers applied to all responses.
 */
const SECURITY_HEADERS = {
    'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
} as const;

/**
 * Standard headers for redirect responses.
 * Cache-Control prevents caching of logout redirects.
 */
const REDIRECT_HEADERS = {
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
    ...SECURITY_HEADERS,
} as const;

/**
 * Headers for HTML responses.
 * Includes security headers to prevent XSS and clickjacking.
 * CSP allows inline styles for the logout confirmation page.
 */
const HTML_HEADERS = {
    'Content-Type': 'text/html;charset=UTF-8',
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
    ...SECURITY_HEADERS,
    'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
} as const;

/**
 * Headers for JSON error responses.
 */
const JSON_HEADERS = {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
    ...SECURITY_HEADERS,
} as const;

// =============================================================================
// Cookie Helpers
// =============================================================================

/**
 * Generate a Set-Cookie header to clear the session cookie.
 *
 * Uses secure cookie attributes:
 * - HttpOnly: Prevents JavaScript access
 * - Secure: Only sent over HTTPS
 * - SameSite=Lax: CSRF protection while allowing top-level navigation
 * - Max-Age=0: Immediately expires the cookie
 * - Path=/: Applies to all paths
 *
 * @param cookieName - Name of the session cookie
 * @param domain - Cookie domain (optional)
 * @returns Set-Cookie header value
 */
export function buildClearCookieHeader(cookieName: string, domain?: string): string {
    const parts = [
        `${cookieName}=`,
        'Max-Age=0',
        'Path=/',
        'HttpOnly',
        'Secure',
        'SameSite=Lax',
    ];

    // __Host- prefix requires no Domain attribute (per cookie prefixes spec)
    if (domain && !cookieName.startsWith('__Host-')) {
        parts.push(`Domain=${domain}`);
    }

    return parts.join('; ');
}

// =============================================================================
// Redirect Responses
// =============================================================================

/**
 * Return a redirect response to the post_logout_redirect_uri.
 *
 * Per OIDC RP-Initiated Logout 1.0 Section 3:
 * - Redirect to post_logout_redirect_uri after successful logout
 * - Include state parameter if provided
 * - Clear session cookie via Set-Cookie header
 *
 * @param redirectUri - The validated post_logout_redirect_uri
 * @param state - Optional state parameter to include
 * @param clearCookieHeader - Set-Cookie header to clear session
 * @returns HTTP 303 redirect response
 */
export function logoutRedirect(
    redirectUri: string,
    state?: string,
    clearCookieHeader?: string
): APIGatewayProxyResultV2 {
    const url = new URL(redirectUri);

    if (state) {
        url.searchParams.set('state', state);
    }

    const headers: Record<string, string> = {
        ...REDIRECT_HEADERS,
        Location: url.toString(),
    };

    if (clearCookieHeader) {
        headers['Set-Cookie'] = clearCookieHeader;
    }

    return {
        statusCode: 303,
        headers,
        body: '',
    };
}

// =============================================================================
// Logout Confirmation Page
// =============================================================================

/**
 * Escape HTML special characters to prevent XSS.
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
 * Return a logout confirmation HTML page.
 *
 * Displayed when no valid post_logout_redirect_uri is provided.
 * Confirms to the user that they have been logged out.
 *
 * @param issuer - The issuer URL for display
 * @param clearCookieHeader - Set-Cookie header to clear session
 * @returns HTTP 200 response with HTML body
 */
export function logoutConfirmationPage(
    issuer: string,
    clearCookieHeader?: string
): APIGatewayProxyResultV2 {
    const escapedIssuer = escapeHtml(issuer);

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Logged Out</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background-color: #f5f5f5;
        }
        .container {
            text-align: center;
            padding: 2rem;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            max-width: 400px;
        }
        h1 {
            color: #333;
            margin-bottom: 1rem;
        }
        p {
            color: #666;
            margin-bottom: 0.5rem;
        }
        .issuer {
            font-size: 0.875rem;
            color: #999;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>You have been logged out</h1>
        <p>Your session has been terminated successfully.</p>
        <p class="issuer">${escapedIssuer}</p>
    </div>
</body>
</html>`;

    const headers: Record<string, string> = { ...HTML_HEADERS };

    if (clearCookieHeader) {
        headers['Set-Cookie'] = clearCookieHeader;
    }

    return {
        statusCode: 200,
        headers,
        body: html,
    };
}

// =============================================================================
// Error Responses
// =============================================================================

/**
 * Return an error response for invalid logout requests.
 *
 * Per OIDC RP-Initiated Logout 1.0, errors should be displayed to the user
 * rather than redirected (since we can't trust the redirect URI).
 *
 * @param error - Error code
 * @param description - Human-readable error description
 * @returns HTTP 400 response with JSON body
 */
export function logoutError(
    error: string,
    description: string
): APIGatewayProxyResultV2 {
    return {
        statusCode: 400,
        headers: JSON_HEADERS,
        body: JSON.stringify({
            error,
            error_description: description,
        }),
    };
}

/**
 * Return a server error response.
 *
 * @param description - Human-readable error description
 * @returns HTTP 500 response with JSON body
 */
export function serverError(description?: string): APIGatewayProxyResultV2 {
    return {
        statusCode: 500,
        headers: JSON_HEADERS,
        body: JSON.stringify({
            error: 'server_error',
            error_description: description || 'An unexpected error occurred',
        }),
    };
}
