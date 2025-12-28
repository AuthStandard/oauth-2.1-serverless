/**
 * OAuth Server - Login Form Template Renderer
 *
 * Uses precompiled Handlebars templates for zero runtime compilation overhead.
 * Templates are compiled at build time by @oauth-server/templates.
 */

import { render as renderLogin, type LoginData } from './templates/login';
import type { LoginFormParams } from './types';

// =============================================================================
// Error Messages
// =============================================================================

const ERROR_MESSAGES: Record<string, string> = {
    invalid_credentials: 'Invalid email or password. Please try again.',
    csrf_invalid: 'Security validation failed. Please try again.',
    session_expired: 'Your session has expired. Please start over.',
    account_locked: 'Your account has been temporarily locked. Please try again later.',
    account_inactive: 'Your account is not active. Please contact support.',
    invalid_request: 'Invalid request. Please try again.',
};

/**
 * Get a user-friendly error message for an error code.
 */
export function getErrorMessage(errorCode: string | undefined): string | undefined {
    if (!errorCode) return undefined;
    return ERROR_MESSAGES[errorCode] || errorCode;
}

// =============================================================================
// Template Rendering
// =============================================================================

/**
 * Render the login form HTML.
 * All values are automatically HTML-escaped by Handlebars.
 */
export function renderLoginForm(params: LoginFormParams): string {
    const data: LoginData = {
        sessionId: params.sessionId,
        csrfToken: params.csrfToken,
        verifyUrl: params.verifyUrl,
        brandName: params.brandName || 'OAuth Server',
        error: params.error,
    };
    return renderLogin(data);
}
