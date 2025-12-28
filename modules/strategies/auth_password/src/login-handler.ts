/**
 * OAuth Server - Password Authentication Login Handler
 *
 * Lambda handler for GET /auth/password/login
 * Renders the login form for email/password authentication.
 *
 * Security Features:
 * - CSRF token generation bound to session ID
 * - Session validation before rendering form
 * - Security headers (X-Frame-Options, X-Content-Type-Options)
 * - No caching of authentication pages
 *
 * Flow:
 * 1. Validate session_id from query parameters
 * 2. Fetch session from DynamoDB to ensure it's valid and not expired
 * 3. Generate CSRF token for form protection
 * 4. Return HTML login form with security headers
 */

import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2, Context } from 'aws-lambda';
import { createLogger, generateCsrfToken } from '@oauth-server/shared';
import { getLoginConfig } from './config';
import { getSession } from './db';
import { htmlResponse, errorResponse } from './responses';
import { renderLoginForm, getErrorMessage } from './template';
import { isSessionExpired } from './validation';

// =============================================================================
// Lambda Handler
// =============================================================================

export const handler = async (
    event: APIGatewayProxyEventV2,
    context: Context
): Promise<APIGatewayProxyResultV2> => {
    const log = createLogger(event, context);

    try {
        log.info('Login page requested', { path: event.requestContext.http.path });

        const sessionId = event.queryStringParameters?.session_id;

        if (!sessionId) {
            log.warn('Missing session_id parameter');
            return errorResponse(400, 'invalid_request', 'Missing required parameter: session_id');
        }

        const config = getLoginConfig();

        const session = await getSession(config.tableName, sessionId);

        if (!session) {
            log.warn('Session not found', { sessionId });
            return errorResponse(400, 'invalid_request', 'Invalid or expired session');
        }

        if (isSessionExpired(session.ttl)) {
            log.warn('Session expired', { sessionId, ttl: session.ttl });
            return errorResponse(400, 'invalid_request', 'Session has expired');
        }

        const csrfToken = generateCsrfToken(sessionId, config.csrfSecret);

        const errorCode = event.queryStringParameters?.error;
        const displayError = getErrorMessage(errorCode);

        log.info('Rendering login form', { sessionId, clientId: session.clientId });

        return htmlResponse(
            renderLoginForm({
                sessionId,
                csrfToken,
                verifyUrl: config.verifyUrl,
                error: displayError,
                brandName: config.brandName,
            })
        );
    } catch (err) {
        const error = err as Error;
        log.error('Login handler error', { error: error.message, stack: error.stack });
        return errorResponse(500, 'server_error', 'An unexpected error occurred');
    }
};
