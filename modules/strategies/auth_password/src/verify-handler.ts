/**
 * OAuth Server - Password Authentication Verify Handler
 *
 * Lambda handler for POST /auth/password/verify
 * Validates credentials and completes the authentication flow.
 *
 * Security Features:
 * - CSRF token validation with constant-time comparison
 * - Argon2id password hashing (memory-hard, GPU-resistant)
 * - Brute force protection with account lockout
 * - SOC2-compliant audit logging for all authentication events
 * - No credential exposure in logs or error messages
 *
 * Flow:
 * 1. Parse form body (email, password, session_id, csrf_token)
 * 2. Validate CSRF token
 * 3. Fetch and validate session from DynamoDB
 * 4. Fetch user by email
 * 5. Check account lockout status
 * 6. Verify password using Argon2id
 * 7. On success: Reset failed attempts, update session, redirect to callback
 * 8. On failure: Increment failed attempts, check lockout threshold, redirect with error
 */

import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2, Context } from 'aws-lambda';
import { argon2Verify } from 'hash-wasm';
import {
    createLogger,
    withContext,
    verifyCsrfToken,
    normalizeEmail,
} from '@oauth-server/shared';
import { getVerifyConfig } from './config';
import {
    getSession,
    getUserByEmail,
    updateSessionWithUser,
    incrementFailedAttempts,
    resetFailedAttempts,
    lockUserAccount,
} from './db';
import { parseFormBody } from './form-parser';
import { errorResponse, redirect, redirectToLoginWithError } from './responses';
import { isSessionExpired, isAccountLocked, calculateLockoutExpiry } from './validation';

// =============================================================================
// Lambda Handler
// =============================================================================

export const handler = async (
    event: APIGatewayProxyEventV2,
    context: Context
): Promise<APIGatewayProxyResultV2> => {
    const log = createLogger(event, context);
    const audit = withContext(event, context);

    try {
        log.info('Verify credentials request', { path: event.requestContext.http.path });

        const config = getVerifyConfig();

        const formData = parseFormBody(event.body, event.isBase64Encoded);
        const { email, password, session_id: sessionId, csrf_token: csrfToken } = formData;

        // Validate required fields
        if (!sessionId || !email || !password || !csrfToken) {
            log.warn('Missing required form fields', {
                hasEmail: !!email,
                hasPassword: !!password,
                hasSessionId: !!sessionId,
                hasCsrfToken: !!csrfToken,
            });
            return redirectToLoginWithError(config.loginUrl, sessionId || '', 'invalid_request');
        }

        // Validate CSRF token
        if (!verifyCsrfToken(sessionId, csrfToken, config.csrfSecret)) {
            log.warn('CSRF validation failed', { sessionId });
            return redirectToLoginWithError(config.loginUrl, sessionId, 'csrf_invalid');
        }

        // Fetch session from DynamoDB
        const session = await getSession(config.tableName, sessionId);

        if (!session) {
            log.warn('Session not found', { sessionId });
            return errorResponse(400, 'invalid_request', 'Invalid or expired session');
        }

        if (isSessionExpired(session.ttl)) {
            log.warn('Session expired', { sessionId });
            return redirectToLoginWithError(config.loginUrl, sessionId, 'session_expired');
        }

        const emailNormalized = normalizeEmail(email);

        // Fetch user by email
        const user = await getUserByEmail(config.tableName, emailNormalized);

        if (!user) {
            audit.loginFailure({ method: 'password', email: emailNormalized, reason: 'user_not_found' });
            log.warn('User not found', { email: emailNormalized });
            return redirectToLoginWithError(config.loginUrl, sessionId, 'invalid_credentials');
        }

        // Check account lockout
        if (isAccountLocked(user.lockedUntil)) {
            audit.loginFailure({ method: 'password', email: emailNormalized, reason: 'account_locked' });
            log.warn('Account is locked', { sub: user.sub, lockedUntil: user.lockedUntil });
            return redirectToLoginWithError(config.loginUrl, sessionId, 'account_locked');
        }

        // Check user status
        if (user.status !== 'ACTIVE') {
            audit.loginFailure({ method: 'password', email: emailNormalized, reason: 'account_inactive' });
            log.warn('User account not active', { sub: user.sub, status: user.status });
            return redirectToLoginWithError(config.loginUrl, sessionId, 'account_inactive');
        }

        // Check if user has password set
        if (!user.passwordHash) {
            audit.loginFailure({ method: 'password', email: emailNormalized, reason: 'no_password_set' });
            log.warn('User has no password set', { sub: user.sub });
            return redirectToLoginWithError(config.loginUrl, sessionId, 'invalid_credentials');
        }

        // Verify password using Argon2
        let passwordValid = false;
        try {
            passwordValid = await argon2Verify({
                password,
                hash: user.passwordHash,
            });
        } catch (err) {
            log.error('Argon2 verification error', { error: (err as Error).message });
            passwordValid = false;
        }

        if (!passwordValid) {
            const failedAttempts = await incrementFailedAttempts(config.tableName, user.sub);

            // Check if we should lock the account
            if (failedAttempts >= config.maxFailedAttempts) {
                const lockedUntil = calculateLockoutExpiry(config.lockoutDurationSeconds);
                await lockUserAccount(config.tableName, user.sub, lockedUntil);

                // Log account locked - use loginFailure with detailed reason
                audit.loginFailure({
                    method: 'password',
                    email: emailNormalized,
                    reason: `account_locked_after_${failedAttempts}_attempts`,
                });

                log.warn('Account locked due to failed attempts', {
                    sub: user.sub,
                    failedAttempts,
                    lockedUntil,
                });

                return redirectToLoginWithError(config.loginUrl, sessionId, 'account_locked');
            }

            audit.loginFailure({ method: 'password', email: emailNormalized, reason: 'invalid_password' });
            log.warn('Password verification failed', { email: emailNormalized, failedAttempts });
            return redirectToLoginWithError(config.loginUrl, sessionId, 'invalid_credentials');
        }

        // =========================================================================
        // SUCCESS: Reset failed attempts, check MFA, update session
        // =========================================================================

        await resetFailedAttempts(config.tableName, user.sub);

        // Check if MFA is enabled for this user
        if (user.mfaEnabled && config.mfaValidateUrl) {
            // MFA is required - update session with pending MFA status
            const sessionUpdated = await updateSessionWithUser(
                config.tableName,
                sessionId,
                user.sub,
                true // pendingMfa = true
            );

            if (!sessionUpdated) {
                log.warn('Session update failed - already authenticated or expired', { sessionId, sub: user.sub });
                return errorResponse(400, 'invalid_request', 'Session is no longer valid');
            }

            audit.loginSuccess(
                { type: 'USER', sub: user.sub },
                { method: 'password', email: emailNormalized, mfaPending: true }
            );
            log.info('Password verified, MFA required', { sub: user.sub, sessionId });

            // Redirect to MFA validation page
            const mfaPath = config.mfaValidateUrl.startsWith('/')
                ? config.mfaValidateUrl
                : `/${config.mfaValidateUrl}`;
            const mfaRedirectUrl = `${mfaPath}?session_id=${encodeURIComponent(sessionId)}`;

            return redirect(mfaRedirectUrl);
        }

        // No MFA required - complete authentication
        const sessionUpdated = await updateSessionWithUser(config.tableName, sessionId, user.sub);

        if (!sessionUpdated) {
            log.warn('Session update failed - already authenticated or expired', { sessionId, sub: user.sub });
            return errorResponse(400, 'invalid_request', 'Session is no longer valid');
        }

        audit.loginSuccess({ type: 'USER', sub: user.sub }, { method: 'password', email: emailNormalized });
        log.info('Login successful', { sub: user.sub, sessionId });

        const callbackPath = config.callbackUrl.startsWith('/')
            ? config.callbackUrl
            : `/${config.callbackUrl}`;
        const redirectUrl = `${callbackPath}?session_id=${encodeURIComponent(sessionId)}`;

        return redirect(redirectUrl);
    } catch (err) {
        const error = err as Error;
        log.error('Verify handler error', { error: error.message, stack: error.stack });
        return errorResponse(500, 'server_error', 'An unexpected error occurred');
    }
};
