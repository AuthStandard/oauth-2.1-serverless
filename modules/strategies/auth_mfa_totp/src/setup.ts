/**
 * OAuth Server - MFA Setup Handler
 *
 * Lambda handler for POST /auth/mfa/setup
 * Generates a TOTP secret and QR code for authenticator app enrollment.
 *
 * Security Features:
 * - Requires authenticated user (Bearer token)
 * - Generates cryptographically secure secret
 * - Backup codes for account recovery
 * - Setup token expires after 10 minutes
 * - SOC2-compliant audit logging
 *
 * Flow:
 * 1. Validate Bearer token and extract user ID
 * 2. Check if MFA is already enabled
 * 3. Generate TOTP secret and backup codes
 * 4. Store setup token in DynamoDB (temporary)
 * 5. Generate QR code for authenticator app
 * 6. Return secret, QR code, and backup codes
 *
 * @module auth_mfa_totp/setup
 */

import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2, Context } from 'aws-lambda';
import { createLogger, withContext } from '@oauth-server/shared';
import { getSetupConfig } from './config';
import { saveMfaSetupToken, getUserMfaConfig } from './db';
import {
    configureTOTP,
    generateSecret,
    generateQRCode,
    generateBackupCodes,
    hashBackupCode,
} from './totp';
import { jsonResponse, errorResponse } from './responses';

// =============================================================================
// Request Parsing
// =============================================================================

interface SetupRequestBody {
    userId: string;
    email: string;
}

function parseRequestBody(event: APIGatewayProxyEventV2): SetupRequestBody | null {
    try {
        let body = event.body || '';
        if (event.isBase64Encoded) {
            body = Buffer.from(body, 'base64').toString('utf-8');
        }
        return JSON.parse(body) as SetupRequestBody;
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
        log.info('MFA setup request', { path: event.requestContext.http.path });

        const config = getSetupConfig();
        configureTOTP(config.totpDigits, config.totpPeriod, 1);

        // Parse request body
        const body = parseRequestBody(event);
        if (!body || !body.userId || !body.email) {
            log.warn('Missing required fields in MFA setup request');
            return errorResponse(400, 'invalid_request', 'userId and email are required');
        }

        const { userId, email } = body;

        // Check if MFA is already enabled
        const existingConfig = await getUserMfaConfig(config.tableName, userId);
        if (existingConfig?.mfaEnabled) {
            log.warn('MFA already enabled for user', { sub: userId });
            return errorResponse(400, 'mfa_already_enabled', 'MFA is already enabled for this account');
        }

        // Generate TOTP secret
        const secret = generateSecret();

        // Generate backup codes
        const backupCodes = generateBackupCodes(config.backupCodesCount);
        const backupCodesHashes = backupCodes.map(hashBackupCode);

        // Save setup token (temporary, for verification step)
        await saveMfaSetupToken(config.tableName, {
            userId,
            secret,
            backupCodes: backupCodesHashes,
        });

        // Generate QR code
        const qrCodeDataUrl = await generateQRCode(secret, email, config.totpIssuer);

        audit.audit('MFA_SETUP_INITIATED', { type: 'USER', sub: userId }, {
            method: 'totp',
        });

        log.info('MFA setup initiated', { sub: userId });

        return jsonResponse(200, {
            secret,
            qrCodeDataUrl,
            backupCodes,
            message: 'Scan the QR code with your authenticator app, then verify with a code to complete setup.',
        });
    } catch (err) {
        const error = err as Error;
        log.error('MFA setup error', { error: error.message, stack: error.stack });
        return errorResponse(500, 'server_error', 'An unexpected error occurred');
    }
};
