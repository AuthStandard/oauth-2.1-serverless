/**
 * OAuth Server - MFA Disable Handler
 *
 * Lambda handler for POST /auth/mfa/disable
 * Disables MFA for a user after verifying their current TOTP code.
 *
 * Security Features:
 * - Requires valid TOTP code to disable (prevents unauthorized disable)
 * - SOC2-compliant audit logging
 * - Removes all MFA-related data from user profile
 *
 * Flow:
 * 1. Parse user ID and TOTP code from request
 * 2. Fetch user's MFA configuration
 * 3. Verify TOTP code
 * 4. Disable MFA on user profile
 * 5. Return success
 *
 * @module auth_mfa_totp/disable
 */

import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2, Context } from 'aws-lambda';
import { createLogger, withContext } from '@oauth-server/shared';
import { getDisableConfig } from './config';
import { getUserMfaConfig, disableUserMfa } from './db';
import { configureTOTP, verifyTOTP } from './totp';
import { jsonResponse, errorResponse } from './responses';

// =============================================================================
// Request Parsing
// =============================================================================

interface DisableRequestBody {
    userId: string;
    code: string;
}

function parseRequestBody(event: APIGatewayProxyEventV2): DisableRequestBody | null {
    try {
        let body = event.body || '';
        if (event.isBase64Encoded) {
            body = Buffer.from(body, 'base64').toString('utf-8');
        }
        return JSON.parse(body) as DisableRequestBody;
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
        log.info('MFA disable request', { path: event.requestContext.http.path });

        const config = getDisableConfig();
        configureTOTP(config.totpDigits, config.totpPeriod, config.totpWindow);

        // Parse request body
        const body = parseRequestBody(event);
        if (!body || !body.userId || !body.code) {
            log.warn('Missing required fields in MFA disable request');
            return errorResponse(400, 'invalid_request', 'userId and code are required');
        }

        const { userId, code } = body;

        // Validate code format
        if (!/^\d{6,8}$/.test(code)) {
            log.warn('Invalid TOTP code format', { sub: userId });
            return errorResponse(400, 'invalid_request', 'Code must be 6 or 8 digits');
        }

        // Fetch user's MFA configuration
        const mfaConfig = await getUserMfaConfig(config.tableName, userId);
        if (!mfaConfig?.mfaEnabled || !mfaConfig.totpSecret) {
            log.warn('MFA not enabled for user', { sub: userId });
            return errorResponse(400, 'mfa_not_enabled', 'MFA is not enabled for this account');
        }

        // Verify TOTP code
        const isValid = verifyTOTP(code, mfaConfig.totpSecret);
        if (!isValid) {
            log.warn('Invalid TOTP code for MFA disable', { sub: userId });
            audit.audit('MFA_DISABLE_FAILED', { type: 'USER', sub: userId }, {
                reason: 'invalid_code',
            });
            return errorResponse(400, 'invalid_code', 'Invalid verification code');
        }

        // Disable MFA
        const disabled = await disableUserMfa(config.tableName, userId);
        if (!disabled) {
            log.error('Failed to disable MFA for user', { sub: userId });
            return errorResponse(500, 'server_error', 'Failed to disable MFA');
        }

        audit.audit('MFA_DISABLED', { type: 'USER', sub: userId }, {
            method: 'totp',
        });

        log.info('MFA disabled successfully', { sub: userId });

        return jsonResponse(200, {
            message: 'MFA has been disabled successfully.',
            mfaEnabled: false,
        });
    } catch (err) {
        const error = err as Error;
        log.error('MFA disable error', { error: error.message, stack: error.stack });
        return errorResponse(500, 'server_error', 'An unexpected error occurred');
    }
};
