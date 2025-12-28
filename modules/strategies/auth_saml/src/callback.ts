/**
 * SAML Strategy - Assertion Consumer Service (ACS) Handler
 *
 * Lambda handler for POST /auth/saml/callback
 * Processes SAML responses from Identity Providers (Okta, Azure AD, etc.)
 *
 * Flow:
 * 1. Parse SAML Response from POST body
 * 2. Validate assertion time conditions
 * 3. Validate XML signature using IdP certificate
 * 4. Validate audience restriction
 * 5. Extract user attributes from assertion
 * 6. JIT provision user if not exists
 * 7. Update login session as authenticated
 * 8. Redirect to OAuth callback
 *
 * @see https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
 */

import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2, Context } from 'aws-lambda';
import { randomUUID } from 'node:crypto';
import { GetCommand, PutCommand, UpdateCommand, QueryCommand } from '@aws-sdk/lib-dynamodb';
import { createLogger, withContext } from '@oauth-server/shared';
import { getDocClient } from './dynamo-client';
import { redirect, errorResponse } from './response';
import {
    parseSamlResponse,
    validateSignature,
    validateTimeConditions,
    validateAudience,
    getEmailFromAssertion,
    getNameFromAssertion,
} from './saml-parser';
import type {
    CallbackEnvConfig,
    SAMLProviderItem,
    LoginSessionItem,
    UserItem,
} from './types';

// =============================================================================
// Environment Configuration
// =============================================================================

function getEnvConfig(): CallbackEnvConfig {
    const tableName = process.env.TABLE_NAME;
    const callbackUrl = process.env.CALLBACK_URL;
    const entityId = process.env.ENTITY_ID;

    if (!tableName) {
        throw new Error('TABLE_NAME environment variable is required');
    }

    if (!callbackUrl) {
        throw new Error('CALLBACK_URL environment variable is required');
    }

    if (!entityId) {
        throw new Error('ENTITY_ID environment variable is required');
    }

    return { tableName, callbackUrl, entityId };
}

// =============================================================================
// Form Body Parser
// =============================================================================

function parseFormBody(
    body: string | null,
    isBase64Encoded: boolean
): Record<string, string> {
    if (!body) return {};

    const decodedBody = isBase64Encoded
        ? Buffer.from(body, 'base64').toString('utf-8')
        : body;

    const params = new URLSearchParams(decodedBody);
    const result: Record<string, string> = {};

    for (const [key, value] of params) {
        result[key] = value;
    }

    return result;
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
        log.info('SAML callback received');

        const config = getEnvConfig();
        const formData = parseFormBody(event.body ?? null, event.isBase64Encoded);

        // Extract SAML Response and RelayState
        const samlResponse = formData.SAMLResponse;
        const relayState = formData.RelayState;

        if (!samlResponse) {
            log.warn('Missing SAMLResponse in callback');
            return errorResponse(400, 'invalid_request', 'Missing SAMLResponse');
        }

        if (!relayState) {
            log.warn('Missing RelayState in callback');
            return errorResponse(400, 'invalid_request', 'Missing RelayState');
        }

        // Parse SAML assertion
        let assertion;
        try {
            assertion = parseSamlResponse(samlResponse);
        } catch (parseError) {
            log.warn('Failed to parse SAML response', { error: (parseError as Error).message });
            return errorResponse(400, 'invalid_saml_response', 'Failed to parse SAML response');
        }

        log.info('SAML assertion parsed', {
            issuer: assertion.issuer,
            nameId: assertion.nameId,
        });

        // Validate time conditions (with 5 minute clock skew tolerance)
        const timeValidation = validateTimeConditions(assertion, 300);
        if (!timeValidation.valid) {
            log.warn('SAML assertion time validation failed', { error: timeValidation.error });
            return errorResponse(400, 'invalid_assertion', timeValidation.error!);
        }

        const client = getDocClient();

        // Fetch SAML provider configuration
        const providerResult = await client.send(
            new GetCommand({
                TableName: config.tableName,
                Key: { PK: `SAML#${assertion.issuer}`, SK: 'CONFIG' },
            })
        );

        if (!providerResult.Item) {
            log.warn('Unknown SAML issuer', { issuer: assertion.issuer });
            return errorResponse(400, 'invalid_issuer', 'Unknown identity provider');
        }

        const provider = providerResult.Item as SAMLProviderItem;

        if (!provider.enabled) {
            log.warn('SAML provider disabled', { issuer: assertion.issuer });
            return errorResponse(400, 'provider_disabled', 'Identity provider is disabled');
        }

        // Validate audience restriction
        if (!validateAudience(assertion, config.entityId)) {
            log.warn('SAML audience mismatch', {
                expected: config.entityId,
                received: assertion.audience,
            });
            return errorResponse(400, 'invalid_audience', 'Assertion audience does not match');
        }

        // Validate XML signature
        if (!validateSignature(samlResponse, provider.certPem)) {
            audit.samlAssertionReceived(
                { type: 'ANONYMOUS' },
                {
                    issuer: assertion.issuer,
                    assertionId: assertion.inResponseTo || 'unknown',
                    valid: false,
                    validationError: 'signature_invalid',
                    nameId: assertion.nameId,
                }
            );

            log.warn('SAML signature validation failed', { issuer: assertion.issuer });
            return errorResponse(400, 'invalid_signature', 'SAML signature validation failed');
        }

        // Extract email from assertion
        const email = getEmailFromAssertion(assertion, provider.attributeMapping);
        if (!email) {
            log.warn('Could not extract email from SAML assertion');
            return errorResponse(400, 'missing_email', 'Email not found in SAML assertion');
        }

        // Fetch login session
        const sessionResult = await client.send(
            new GetCommand({
                TableName: config.tableName,
                Key: { PK: `SESSION#${relayState}`, SK: 'METADATA' },
            })
        );

        if (!sessionResult.Item) {
            log.warn('Session not found', { sessionId: relayState });
            return errorResponse(400, 'invalid_session', 'Session not found or expired');
        }

        const session = sessionResult.Item as LoginSessionItem;

        // Check session TTL
        const nowEpochSeconds = Math.floor(Date.now() / 1000);
        if (session.ttl && session.ttl < nowEpochSeconds) {
            log.warn('Session expired', { sessionId: relayState });
            return errorResponse(400, 'session_expired', 'Session has expired');
        }

        // Extract name attributes
        const { givenName, familyName } = getNameFromAssertion(
            assertion,
            provider.attributeMapping
        );

        // Find or create user (JIT provisioning)
        const userResult = await findOrCreateUser(
            client,
            config.tableName,
            email,
            givenName,
            familyName,
            assertion.issuer,
            log
        );

        if ('error' in userResult) {
            return userResult.error;
        }

        const { userId, isNew } = userResult;

        // Audit log successful SAML authentication
        audit.samlAssertionReceived(
            { type: 'USER', sub: userId },
            {
                issuer: assertion.issuer,
                assertionId: assertion.inResponseTo || 'unknown',
                valid: true,
                nameId: assertion.nameId,
            }
        );

        audit.loginSuccess(
            { type: 'USER', sub: userId },
            { method: 'saml', email }
        );

        if (isNew) {
            log.info('User JIT provisioned via SAML', { sub: userId, email });
        }

        // Update session with authenticated user
        const timestamp = new Date().toISOString();

        await client.send(
            new UpdateCommand({
                TableName: config.tableName,
                Key: { PK: `SESSION#${relayState}`, SK: 'METADATA' },
                UpdateExpression: 'SET authenticatedUserId = :userId, authenticatedAt = :authAt, updatedAt = :now, authMethod = :method',
                ExpressionAttributeValues: {
                    ':userId': userId,
                    ':authAt': timestamp,
                    ':now': timestamp,
                    ':method': 'saml',
                },
            })
        );

        log.info('SAML authentication successful', {
            sub: userId,
            sessionId: relayState,
            issuer: assertion.issuer,
        });

        // Redirect to OAuth callback
        const callbackPath = config.callbackUrl.startsWith('/')
            ? config.callbackUrl
            : `/${config.callbackUrl}`;
        const redirectUrl = `${callbackPath}?session_id=${encodeURIComponent(relayState)}`;

        return redirect(redirectUrl);
    } catch (err) {
        const error = err as Error;
        log.error('SAML callback error', { error: error.message, stack: error.stack });
        return errorResponse(500, 'server_error', 'An unexpected error occurred');
    }
};

// =============================================================================
// User Provisioning
// =============================================================================

async function findOrCreateUser(
    client: ReturnType<typeof getDocClient>,
    tableName: string,
    email: string,
    givenName: string | undefined,
    familyName: string | undefined,
    _samlIssuer: string,
    log: ReturnType<typeof createLogger>
): Promise<{ userId: string; isNew: boolean } | { error: APIGatewayProxyResultV2 }> {
    // Query user by email
    const userResult = await client.send(
        new QueryCommand({
            TableName: tableName,
            IndexName: 'GSI1',
            KeyConditionExpression: 'GSI1PK = :pk AND GSI1SK = :sk',
            ExpressionAttributeValues: {
                ':pk': `EMAIL#${email}`,
                ':sk': 'USER',
            },
            Limit: 1,
        })
    );

    if (userResult.Items && userResult.Items.length > 0) {
        // Existing user
        const existingUser = userResult.Items[0] as UserItem;

        if (existingUser.status !== 'ACTIVE') {
            log.warn('User account not active', {
                sub: existingUser.sub,
                status: existingUser.status,
            });
            return {
                error: errorResponse(403, 'account_inactive', 'User account is not active'),
            };
        }

        return { userId: existingUser.sub, isNew: false };
    }

    // JIT Provision: Create new user
    const userId = randomUUID();
    const timestamp = new Date().toISOString();

    const newUser: UserItem = {
        PK: `USER#${userId}`,
        SK: 'PROFILE',
        GSI1PK: `EMAIL#${email}`,
        GSI1SK: 'USER',
        sub: userId,
        email,
        emailVerified: true, // SAML IdP verified the email
        status: 'ACTIVE',
        profile: {
            givenName,
            familyName,
        },
        zoneinfo: 'UTC',
        entityType: 'USER',
        createdAt: timestamp,
        updatedAt: timestamp,
        ttl: 0, // No expiration for user records
    };

    await client.send(
        new PutCommand({
            TableName: tableName,
            Item: newUser,
        })
    );

    return { userId, isNew: true };
}
