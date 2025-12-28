/**
 * OAuth Server - MFA Verify Handler
 *
 * Lambda handler for POST /auth/mfa/verify
 * Verifies a TOTP code to complete MFA enrollment.
 *
 * Security Features:
 * - Validates TOTP code against pending setup secret
 * - Enables MFA only after successful verification
 * - Deletes setup token after use (single-use)
 * - SOC2-compliant audit logging
 *
 * Flow:
 * 1. Parse user ID and TOTP code from request
 * 2. Fetch pending setup token from DynamoDB
 * 3. Verify TOTP code against setup secret
 * 4. Enable MFA on user profile
 * 5. Delete setup token
 * 6. Return success
 *
 * @module auth_mfa_totp/verify
 */

import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2, Context } from 'aws-lambda';
import { createLogger, withContext } from '@oauth-server/shared';
import { getVerifyConfig } from './config';
import { getMfaSetupToken, deleteMfaSetupToken, enableUserMfa } from './db';
import { configureTOTP, verifyTOTP } from './totp';
import { jsonResponse, errorResponse } from './responses';

// =============================================================================
// Request Parsing
// =============================================================================

interface VerifyRequestBody {
    userId: string;
    code: string;
}

function parseRequestBody(event: APIGatewayProxyEventV2): VerifyRequestBody | null {
    try {
        let body = event.body || '';
        if (event.isBase64Encoded) {
            body = Buffer.from(body, 'base64').toString('utf-8');
        }
        return JSON.parse(body) as VerifyRequestBody;
    } catch {
        return null;
    }
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
        log.info('MFA verify request', { path: event.requestContext.http.path });

        const config = getVerifyConfig();
        configureTOTP(config.totpDigits, config.totpPeriod, config.totpWindow);

        // Parse request body
        const body = parseRequestBody(event);
        if (!body || !body.userId || !body.code) {
            log.warn('Missing required fields in MFA verify request');
            return errorResponse(400, 'invalid_request', 'userId and code are required');
        }

        const { userId, code } = body;

        // Validate code format (6 or 8 digits)
        if (!/^\d{6,8}$/.test(code)) {
            log.warn('Invalid TOTP code format', { sub: userId });
            return errorResponse(400, 'invalid_request', 'Code must be 6 or 8 digits');
        }

        // Fetch setup token
        const setupToken = await getMfaSetupToken(config.tableName, userId);
        if (!setupToken) {
            log.warn('No pending MFA setup found', { sub: userId });
            return errorResponse(400, 'invalid_request', 'No pending MFA setup found. Please start setup again.');
        }

        // Check if setup token is expired
        const nowEpoch = Math.floor(Date.now() / 1000);
        if (setupToken.ttl < nowEpoch) {
            log.warn('MFA setup token expired', { sub: userId });
            await deleteMfaSetupToken(config.tableName, userId);
            return errorResponse(400, 'invalid_request', 'Setup session expired. Please start setup again.');
        }

        // Verify TOTP code
        const isValid = verifyTOTP(code, setupToken.secret);
        if (!isValid) {
            log.warn('Invalid TOTP code during setup verification', { sub: userId });
            audit.audit('MFA_SETUP_FAILED', { type: 'USER', sub: userId }, {
                reason: 'invalid_code',
            });
            return errorResponse(400, 'invalid_code', 'Invalid verification code. Please try again.');
        }

        // Enable MFA on user profile
        const enabled = await enableUserMfa(
            config.tableName,
            userId,
            setupToken.secret,
            setupToken.backupCodes
        );

        if (!enabled) {
            log.error('Failed to enable MFA for user', { sub: userId });
            return errorResponse(500, 'server_error', 'Failed to enable MFA');
        }

        // Delete setup token (single-use)
        await deleteMfaSetupToken(config.tableName, userId);

        audit.audit('MFA_ENABLED', { type: 'USER', sub: userId }, {
            method: 'totp',
        });

        log.info('MFA enabled successfully', { sub: userId });

        return jsonResponse(200, {
            message: 'MFA has been enabled successfully.',
            mfaEnabled: true,
        });
    } catch (err) {
        const error = err as Error;
        log.error('MFA verify error', { error: error.message, stack: error.stack });
        return errorResponse(500, 'server_error', 'An unexpected error occurred');
    }
};
