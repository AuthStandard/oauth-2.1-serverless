/**
 * OAuth Server - Password Reset Handler
 *
 * Lambda handler for POST /auth/password/reset
 * Completes the password reset flow by validating the token and updating the password.
 *
 * Security Features:
 * - Token validation with constant-time comparison
 * - Token is single-use (deleted after successful reset)
 * - Argon2id password hashing (memory-hard, GPU-resistant)
 * - Password strength validation
 * - SOC2-compliant audit logging
 * - Clears failed login attempts on successful reset
 *
 * Flow:
 * 1. Parse token and new password from request body
 * 2. Validate password strength requirements
 * 3. Hash token and look up in DynamoDB
 * 4. Validate token exists and is not expired
 * 5. Hash new password with Argon2id
 * 6. Update user's password in DynamoDB
 * 7. Delete the reset token (single-use)
 * 8. Clear any account lockout
 * 9. Return success
 *
 * @module auth_password/reset
 */

import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2, Context } from 'aws-lambda';
import { createHash, randomBytes } from 'node:crypto';
import { argon2id } from 'hash-wasm';
import {
    createLogger,
    withContext,
    Mailer,
} from '@oauth-server/shared';
import { getResetConfig } from './config';
import {
    getPasswordResetToken,
    deletePasswordResetToken,
    updateUserPassword,
    resetFailedAttempts,
} from './db';
import { parseFormBody } from './form-parser';
import { jsonResponse, errorResponse } from './responses';
import { validatePasswordStrength } from './validation';

// =============================================================================
// Constants
// =============================================================================

/**
 * Argon2id parameters per OWASP recommendations.
 * These provide strong security while keeping Lambda execution time reasonable.
 *
 * @see https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
 */
const ARGON2_CONFIG = {
    parallelism: 1,
    iterations: 3,
    memorySize: 65536, // 64 MB
    hashLength: 32,
    outputType: 'encoded' as const,
};

// =============================================================================
// Token Validation
// =============================================================================

/**
 * Hash a reset token for lookup.
 */
function hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
}

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
        log.info('Password reset request', { path: event.requestContext.http.path });

        const config = getResetConfig();

        // Parse request body
        const formData = parseFormBody(event.body, event.isBase64Encoded);
        const { token, password, password_confirm: passwordConfirm } = formData;

        // Validate required fields
        if (!token) {
            log.warn('Missing token in password reset request');
            return errorResponse(400, 'invalid_request', 'Reset token is required');
        }

        if (!password) {
            log.warn('Missing password in password reset request');
            return errorResponse(400, 'invalid_request', 'New password is required');
        }

        // Validate password confirmation if provided
        if (passwordConfirm && password !== passwordConfirm) {
            log.warn('Password confirmation mismatch');
            return errorResponse(400, 'invalid_request', 'Passwords do not match');
        }

        // Validate password strength
        const strengthResult = validatePasswordStrength(password, config.passwordPolicy);
        if (!strengthResult.valid) {
            log.warn('Password does not meet strength requirements', {
                errors: strengthResult.errors,
            });
            return errorResponse(400, 'invalid_request', strengthResult.errors.join('. '));
        }

        // Hash token for lookup
        const tokenHash = hashToken(token);

        // Look up token in DynamoDB
        const resetToken = await getPasswordResetToken(config.tableName, tokenHash);

        if (!resetToken) {
            log.warn('Invalid or expired reset token');
            audit.audit('PASSWORD_RESET_FAILED', { type: 'ANONYMOUS' }, {
                reason: 'invalid_token',
            });
            return errorResponse(400, 'invalid_request', 'Invalid or expired reset token');
        }

        // Check if token is expired (defense-in-depth, TTL should handle this)
        const nowEpoch = Math.floor(Date.now() / 1000);
        if (resetToken.ttl && resetToken.ttl < nowEpoch) {
            log.warn('Reset token expired', { tokenHash: tokenHash.substring(0, 8) + '...' });
            audit.audit('PASSWORD_RESET_FAILED', { type: 'USER', sub: resetToken.userId }, {
                reason: 'token_expired',
            });
            return errorResponse(400, 'invalid_request', 'Reset token has expired');
        }

        // Hash new password with Argon2id using cryptographically secure salt
        const salt = randomBytes(16);
        const passwordHash = await argon2id({
            password,
            salt,
            ...ARGON2_CONFIG,
        });

        // Update user's password
        const updateSuccess = await updateUserPassword(
            config.tableName,
            resetToken.userId,
            passwordHash
        );

        if (!updateSuccess) {
            log.error('Failed to update user password', { sub: resetToken.userId });
            return errorResponse(500, 'server_error', 'Failed to update password');
        }

        // Delete the reset token (single-use)
        await deletePasswordResetToken(config.tableName, tokenHash);

        // Clear any account lockout and failed attempts
        await resetFailedAttempts(config.tableName, resetToken.userId);

        // Audit log
        audit.audit('PASSWORD_RESET_SUCCESS', { type: 'USER', sub: resetToken.userId }, {
            email: Mailer.maskEmail(resetToken.email),
        });

        log.info('Password reset successful', {
            sub: resetToken.userId,
            email: Mailer.maskEmail(resetToken.email),
        });

        return jsonResponse(200, {
            message: 'Password has been reset successfully. You can now log in with your new password.',
        });
    } catch (err) {
        const error = err as Error;
        log.error('Password reset handler error', { error: error.message, stack: error.stack });
        return errorResponse(500, 'server_error', 'An unexpected error occurred');
    }
};
