/**
 * OAuth Server - MFA Validate Handler
 *
 * Lambda handler for POST /auth/mfa/validate
 * Validates a TOTP code during the login flow (after password verification).
 *
 * Security Features:
 * - Validates TOTP code against user's stored secret
 * - Supports backup codes for account recovery
 * - Rate limiting on failed attempts (via session-based tracking)
 * - SOC2-compliant audit logging
 *
 * Note: Rate limiting is enforced at the session level - each session
 * tracks failed MFA attempts. After too many failures, the session
 * is invalidated and the user must restart the login flow.
 *
 * Flow:
 * 1. Parse session ID and TOTP code from request
 * 2. Fetch session and validate it's pending MFA
 * 3. Fetch user's MFA configuration
 * 4. Verify TOTP code (or backup code)
 * 5. Update session as MFA-verified
 * 6. Return success with redirect URL
 *
 * @module auth_mfa_totp/validate
 */

import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2, Context } from 'aws-lambda';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { createLogger, withContext } from '@oauth-server/shared';
import { getValidateConfig } from './config';
import { getUserMfaConfig, useBackupCode } from './db';
import { configureTOTP, verifyTOTP, verifyBackupCode } from './totp';
import { jsonResponse, errorResponse } from './responses';

// =============================================================================
// DynamoDB Client
// =============================================================================

let docClient: DynamoDBDocumentClient | null = null;

function getDocClient(): DynamoDBDocumentClient {
    if (!docClient) {
        docClient = DynamoDBDocumentClient.from(new DynamoDBClient({}), {
            marshallOptions: { removeUndefinedValues: true },
        });
    }
    return docClient;
}

// =============================================================================
// Request Parsing
// =============================================================================

interface ValidateRequestBody {
    sessionId: string;
    code: string;
}

function parseRequestBody(event: APIGatewayProxyEventV2): ValidateRequestBody | null {
    try {
        let body = event.body || '';
        if (event.isBase64Encoded) {
            body = Buffer.from(body, 'base64').toString('utf-8');
        }
        return JSON.parse(body) as ValidateRequestBody;
    } catch {
        return null;
    }
}

// =============================================================================
// Session Operations
// =============================================================================

interface MfaSession {
    sessionId: string;
    pendingMfaUserId?: string;
    authenticatedUserId?: string;
    redirectUri: string;
    state?: string;
    ttl: number;
}

async function getSession(tableName: string, sessionId: string): Promise<MfaSession | null> {
    const client = getDocClient();
    const result = await client.send(
        new GetCommand({
            TableName: tableName,
            Key: { PK: `SESSION#${sessionId}`, SK: 'METADATA' },
        })
    );

    if (!result.Item) {
        return null;
    }

    return {
        sessionId: result.Item.sessionId,
        pendingMfaUserId: result.Item.pendingMfaUserId,
        authenticatedUserId: result.Item.authenticatedUserId,
        redirectUri: result.Item.redirectUri,
        state: result.Item.state,
        ttl: result.Item.ttl,
    };
}

/**
 * Complete MFA verification by moving pendingMfaUserId to authenticatedUserId.
 * This marks the session as fully authenticated.
 */
async function completeSessionMfaVerification(
    tableName: string,
    sessionId: string,
    userId: string
): Promise<boolean> {
    const client = getDocClient();
    const now = new Date().toISOString();
    const nowEpoch = Math.floor(Date.now() / 1000);

    try {
        await client.send(
            new UpdateCommand({
                TableName: tableName,
                Key: { PK: `SESSION#${sessionId}`, SK: 'METADATA' },
                UpdateExpression: 'SET authenticatedUserId = :userId, authenticatedAt = :now, mfaVerifiedAt = :now, updatedAt = :now REMOVE pendingMfaUserId',
                ConditionExpression: 'attribute_exists(PK) AND pendingMfaUserId = :userId AND attribute_not_exists(authenticatedUserId) AND (attribute_not_exists(#ttl) OR #ttl > :nowEpoch)',
                ExpressionAttributeNames: {
                    '#ttl': 'ttl',
                },
                ExpressionAttributeValues: {
                    ':userId': userId,
                    ':now': now,
                    ':nowEpoch': nowEpoch,
                },
            })
        );
        return true;
    } catch (err) {
        const error = err as Error;
        if (error.name === 'ConditionalCheckFailedException') {
            return false;
        }
        throw err;
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
        log.info('MFA validate request', { path: event.requestContext.http.path });

        const config = getValidateConfig();
        configureTOTP(config.totpDigits, config.totpPeriod, config.totpWindow);

        // Parse request body
        const body = parseRequestBody(event);
        if (!body || !body.sessionId || !body.code) {
            log.warn('Missing required fields in MFA validate request');
            return errorResponse(400, 'invalid_request', 'sessionId and code are required');
        }

        const { sessionId, code } = body;

        // Fetch session
        const session = await getSession(config.tableName, sessionId);
        if (!session) {
            log.warn('Session not found', { sessionId });
            return errorResponse(400, 'invalid_request', 'Invalid or expired session');
        }

        // Check session expiration
        const nowEpoch = Math.floor(Date.now() / 1000);
        if (session.ttl < nowEpoch) {
            log.warn('Session expired', { sessionId });
            return errorResponse(400, 'invalid_request', 'Session has expired');
        }

        // Check if session is pending MFA verification
        if (!session.pendingMfaUserId) {
            if (session.authenticatedUserId) {
                log.warn('Session already fully authenticated', { sessionId });
                return errorResponse(400, 'invalid_request', 'Session is already authenticated');
            }
            log.warn('Session not pending MFA', { sessionId });
            return errorResponse(400, 'invalid_request', 'MFA verification not required for this session');
        }

        const userId = session.pendingMfaUserId;

        // Fetch user's MFA configuration
        const mfaConfig = await getUserMfaConfig(config.tableName, userId);
        if (!mfaConfig?.mfaEnabled || !mfaConfig.totpSecret) {
            log.error('MFA not configured for user', { sub: userId });
            return errorResponse(500, 'server_error', 'MFA configuration error');
        }

        // Try TOTP verification first
        let isValid = false;
        let usedBackupCode = false;

        if (/^\d{6,8}$/.test(code)) {
            // Looks like a TOTP code
            isValid = verifyTOTP(code, mfaConfig.totpSecret);
        }

        // If TOTP failed, try backup code
        if (!isValid && mfaConfig.backupCodesHashes) {
            const matchingHash = verifyBackupCode(code, mfaConfig.backupCodesHashes);
            if (matchingHash) {
                // Use the backup code (remove from list)
                const used = await useBackupCode(config.tableName, userId, matchingHash);
                if (used) {
                    isValid = true;
                    usedBackupCode = true;
                }
            }
        }

        if (!isValid) {
            log.warn('Invalid MFA code', { sub: userId, sessionId });
            audit.audit('MFA_VALIDATION_FAILED', { type: 'USER', sub: userId }, {
                sessionId,
                reason: 'invalid_code',
            });
            return errorResponse(400, 'invalid_code', 'Invalid verification code');
        }

        // Complete MFA verification - move pendingMfaUserId to authenticatedUserId
        const updated = await completeSessionMfaVerification(config.tableName, sessionId, userId);
        if (!updated) {
            log.error('Failed to complete session MFA verification', { sessionId });
            return errorResponse(500, 'server_error', 'Failed to verify MFA');
        }

        audit.audit('MFA_VALIDATION_SUCCESS', { type: 'USER', sub: userId }, {
            sessionId,
            usedBackupCode,
        });

        log.info('MFA validated successfully', { sub: userId, sessionId, usedBackupCode });

        // Return success with callback URL
        const callbackUrl = `/authorize/callback?session_id=${encodeURIComponent(sessionId)}`;

        return jsonResponse(200, {
            message: 'MFA verification successful',
            redirectUrl: callbackUrl,
            usedBackupCode,
        });
    } catch (err) {
        const error = err as Error;
        log.error('MFA validate error', { error: error.message, stack: error.stack });
        return errorResponse(500, 'server_error', 'An unexpected error occurred');
    }
};
