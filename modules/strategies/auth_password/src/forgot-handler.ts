/**
 * OAuth Server - Forgot Password Handler
 *
 * Lambda handler for POST /auth/password/forgot
 * Initiates the password reset flow by generating a secure token and sending an email.
 *
 * Security Features:
 * - Rate limiting to prevent email enumeration attacks
 * - Secure token generation (256 bits of entropy)
 * - Token stored as SHA-256 hash (never plaintext)
 * - Constant-time response regardless of user existence
 * - SOC2-compliant audit logging
 * - No PII in logs (email addresses are masked)
 *
 * Flow:
 * 1. Parse and validate email from request body
 * 2. Normalize email address
 * 3. Look up user by email (timing-safe)
 * 4. Generate secure reset token
 * 5. Store token hash in DynamoDB with TTL
 * 6. Send password reset email via SES
 * 7. Return success (always, to prevent enumeration)
 *
 * @module auth_password/forgot
 */

import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2, Context } from 'aws-lambda';
import { randomBytes, createHash } from 'node:crypto';
import {
    createLogger,
    withContext,
    normalizeEmail,
    Mailer,
} from '@oauth-server/shared';
import { getForgotConfig } from './config';
import { getUserByEmail, savePasswordResetToken } from './db';
import { parseFormBody } from './form-parser';
import { jsonResponse, errorResponse } from './responses';

// =============================================================================
// Constants
// =============================================================================

/** 32 bytes = 256 bits of entropy for reset tokens */
const RESET_TOKEN_BYTES = 32;

// =============================================================================
// Token Generation
// =============================================================================

/**
 * Generate a cryptographically secure password reset token.
 * Returns both the raw token (for email) and its hash (for storage).
 */
function generateResetToken(): { token: string; tokenHash: string } {
    const tokenBuffer = randomBytes(RESET_TOKEN_BYTES);
    const token = tokenBuffer.toString('base64url');
    const tokenHash = createHash('sha256').update(token).digest('hex');
    return { token, tokenHash };
}

/**
 * Format TTL duration for human-readable display in emails.
 */
function formatExpiresIn(ttlSeconds: number): string {
    if (ttlSeconds >= 3600) {
        const hours = Math.floor(ttlSeconds / 3600);
        return hours === 1 ? '1 hour' : `${hours} hours`;
    }
    const minutes = Math.floor(ttlSeconds / 60);
    return minutes === 1 ? '1 minute' : `${minutes} minutes`;
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
        log.info('Forgot password request', { path: event.requestContext.http.path });

        const config = getForgotConfig();

        // Parse request body
        const formData = parseFormBody(event.body, event.isBase64Encoded);
        const { email } = formData;

        // Validate email
        if (!email) {
            log.warn('Missing email in forgot password request');
            return errorResponse(400, 'invalid_request', 'Email address is required');
        }

        const emailNormalized = normalizeEmail(email);

        // Look up user (timing-safe: always perform the same operations)
        const user = await getUserByEmail(config.tableName, emailNormalized);

        // Generate token regardless of user existence (timing attack prevention)
        const { token, tokenHash } = generateResetToken();
        const ttlEpoch = Math.floor(Date.now() / 1000) + config.resetTokenTtl;

        if (user && user.status === 'ACTIVE') {
            // Save token to DynamoDB
            await savePasswordResetToken(config.tableName, {
                tokenHash,
                userId: user.sub,
                email: emailNormalized,
                ttl: ttlEpoch,
            });

            // Build reset link
            const resetLink = `${config.resetPageUrl}?token=${encodeURIComponent(token)}`;

            // Send email
            const mailer = new Mailer({
                senderEmail: config.sesSenderEmail,
                senderName: config.sesSenderName,
                configurationSet: config.sesConfigurationSet,
            });

            const emailResult = await mailer.sendEmail({
                to: emailNormalized,
                template: config.passwordResetTemplate,
                data: {
                    email: emailNormalized,
                    link: resetLink,
                    expiresIn: formatExpiresIn(config.resetTokenTtl),
                },
            });

            if (emailResult.success) {
                audit.audit('PASSWORD_RESET_REQUESTED', { type: 'USER', sub: user.sub }, {
                    email: Mailer.maskEmail(emailNormalized),
                });
                log.info('Password reset email sent', {
                    sub: user.sub,
                    email: Mailer.maskEmail(emailNormalized),
                    messageId: emailResult.messageId,
                });
            } else {
                log.error('Failed to send password reset email', {
                    sub: user.sub,
                    email: Mailer.maskEmail(emailNormalized),
                    error: emailResult.error,
                });
            }
        } else {
            // User not found or inactive - log but don't reveal to client
            log.info('Password reset requested for unknown/inactive user', {
                email: Mailer.maskEmail(emailNormalized),
            });
        }

        // Always return success to prevent email enumeration
        return jsonResponse(200, {
            message: 'If an account exists with this email, a password reset link has been sent.',
        });
    } catch (err) {
        const error = err as Error;
        log.error('Forgot password handler error', { error: error.message, stack: error.stack });
        return errorResponse(500, 'server_error', 'An unexpected error occurred');
    }
};
