/**
 * SCIM v2 /Me Endpoint - Self-Service User Profile
 *
 * Implements RFC 7644 Section 3.11 - /Me Authenticated Subject Alias.
 *
 * Endpoints:
 * - GET /scim/v2/Me - Retrieve authenticated user's profile
 * - PATCH /scim/v2/Me - Update authenticated user's profile (limited fields)
 *
 * Security:
 * - Uses standard User Access Token (not Admin Token)
 * - Extracts user identity from JWT 'sub' claim
 * - Restricts updates to safe fields only (name, locale, zoneinfo)
 * - Prevents modification of groups, active status, and enterprise fields
 *
 * @module governance/scim_v2/me
 * @see RFC 7644 Section 3.11 - /Me Authenticated Subject Alias
 */

import type { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { GetCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import type { APIGatewayProxyResultV2 } from 'aws-lambda';
import { AuditLogger, Logger } from '@oauth-server/shared';
import type { UserItem } from '../../../shared_types/user';
import type { EnvConfig, ScimPatchRequest, ScimPatchOperation, ScimName } from './types';
import { userItemToScimUser } from './mapper';
import { scimUserResponse, scimBadRequest, scimNotFound, scimForbidden, scimServerError } from './responses';
import { SCIM_PATCH_SCHEMA, SCIM_ENTERPRISE_USER_SCHEMA } from './types';

// =============================================================================
// Constants
// =============================================================================

/**
 * Fields that are explicitly forbidden for self-service updates.
 * Attempting to modify these returns 403 Forbidden.
 */
const FORBIDDEN_SELF_UPDATE_PATHS = new Set([
    'active',
    'groups',
    'roles',
    'entitlements',
    'userName',
    'emails',
    'password',
    // Enterprise extension fields
    'employeeNumber',
    'costCenter',
    'organization',
    'division',
    'department',
    'manager',
]);

// =============================================================================
// GET /Me Handler
// =============================================================================

/**
 * Handle GET /scim/v2/Me - Retrieve authenticated user's profile.
 *
 * @param userId - User ID extracted from JWT 'sub' claim
 * @param config - Environment configuration
 * @param client - DynamoDB document client
 * @returns SCIM User response (200 OK or error)
 */
export async function handleGetMe(
    userId: string,
    config: EnvConfig,
    client: DynamoDBDocumentClient
): Promise<APIGatewayProxyResultV2> {
    // Fetch user profile from DynamoDB
    const result = await client.send(
        new GetCommand({
            TableName: config.tableName,
            Key: { PK: `USER#${userId}`, SK: 'PROFILE' },
        })
    );

    if (!result.Item) {
        return scimNotFound('User profile not found');
    }

    const user = result.Item as UserItem;
    const scimUser = userItemToScimUser(user, config);

    return scimUserResponse(scimUser, 200);
}

// =============================================================================
// PATCH /Me Handler
// =============================================================================

/**
 * Handle PATCH /scim/v2/Me - Update authenticated user's profile.
 *
 * Restrictions:
 * - Only allows updating name, locale, zoneinfo fields
 * - Returns 403 Forbidden for attempts to modify groups, active, enterprise fields
 *
 * @param userId - User ID extracted from JWT 'sub' claim
 * @param body - SCIM PATCH request body
 * @param config - Environment configuration
 * @param client - DynamoDB document client
 * @param audit - Audit logger
 * @param requestId - Request ID for logging
 * @returns SCIM User response (200 OK or error)
 */
export async function handlePatchMe(
    userId: string,
    body: ScimPatchRequest,
    config: EnvConfig,
    client: DynamoDBDocumentClient,
    audit: AuditLogger,
    requestId: string
): Promise<APIGatewayProxyResultV2> {
    const log = new Logger(requestId);

    // Validate PATCH request structure
    const validation = validateMePatchRequest(body);
    if (!validation.valid) {
        return scimBadRequest(validation.error || 'Invalid request', 'invalidSyntax');
    }

    // Check for forbidden field modifications
    const forbiddenCheck = checkForbiddenFields(body.Operations);
    if (!forbiddenCheck.allowed) {
        log.warn('Forbidden field modification attempted via /Me', {
            userId,
            forbiddenPath: forbiddenCheck.forbiddenPath,
        });
        return scimForbidden(
            `Cannot modify '${forbiddenCheck.forbiddenPath}' via /Me endpoint. ` +
            'This field can only be modified by administrators.'
        );
    }

    // Fetch existing user
    const userResult = await client.send(
        new GetCommand({
            TableName: config.tableName,
            Key: { PK: `USER#${userId}`, SK: 'PROFILE' },
        })
    );

    if (!userResult.Item) {
        return scimNotFound('User profile not found');
    }

    const user = userResult.Item as UserItem;

    // Build update expression from allowed operations
    const updateParams = buildMeUpdateParams(body.Operations, user);
    if (!updateParams) {
        // No valid updates to apply
        const scimUser = userItemToScimUser(user, config);
        return scimUserResponse(scimUser, 200);
    }

    // Apply updates
    try {
        await client.send(
            new UpdateCommand({
                TableName: config.tableName,
                Key: { PK: `USER#${userId}`, SK: 'PROFILE' },
                UpdateExpression: updateParams.updateExpression,
                ExpressionAttributeNames: updateParams.expressionAttributeNames,
                ExpressionAttributeValues: updateParams.expressionAttributeValues,
                ConditionExpression: 'attribute_exists(PK)',
            })
        );
    } catch (err) {
        if ((err as Error).name === 'ConditionalCheckFailedException') {
            return scimNotFound('User profile not found');
        }
        log.error('Failed to update user profile', { error: (err as Error).message });
        return scimServerError('Failed to update profile');
    }

    // Audit the self-service update
    audit.log({
        action: 'USER_UPDATED',
        actor: { type: 'USER', sub: userId },
        details: { userId, updatedFields: Object.keys(updateParams.expressionAttributeValues), selfService: true },
    });

    // Fetch and return updated user
    const updatedResult = await client.send(
        new GetCommand({
            TableName: config.tableName,
            Key: { PK: `USER#${userId}`, SK: 'PROFILE' },
        })
    );

    const updatedUser = updatedResult.Item as UserItem;
    const scimUser = userItemToScimUser(updatedUser, config);

    log.info('User profile updated via /Me', { userId });

    return scimUserResponse(scimUser, 200);
}

// =============================================================================
// Validation Helpers
// =============================================================================

/**
 * Validate PATCH request structure for /Me endpoint.
 */
function validateMePatchRequest(request: ScimPatchRequest): { valid: boolean; error?: string } {
    if (!request.schemas || !Array.isArray(request.schemas)) {
        return { valid: false, error: 'schemas is required' };
    }

    if (!request.schemas.includes(SCIM_PATCH_SCHEMA)) {
        return { valid: false, error: `Invalid schema. Expected: ${SCIM_PATCH_SCHEMA}` };
    }

    if (!request.Operations || !Array.isArray(request.Operations)) {
        return { valid: false, error: 'Operations is required and must be an array' };
    }

    if (request.Operations.length === 0) {
        return { valid: false, error: 'Operations array cannot be empty' };
    }

    for (let i = 0; i < request.Operations.length; i++) {
        const op = request.Operations[i];
        if (!op.op) {
            return { valid: false, error: `Operations[${i}].op is required` };
        }
        const validOps = ['add', 'remove', 'replace'];
        if (!validOps.includes(op.op.toLowerCase())) {
            return { valid: false, error: `Operations[${i}].op must be one of: ${validOps.join(', ')}` };
        }
    }

    return { valid: true };
}

/**
 * Check if any operations attempt to modify forbidden fields.
 */
function checkForbiddenFields(
    operations: readonly ScimPatchOperation[]
): { allowed: boolean; forbiddenPath?: string } {
    for (const op of operations) {
        const path = op.path?.toLowerCase() || '';

        // Check direct forbidden paths
        for (const forbidden of FORBIDDEN_SELF_UPDATE_PATHS) {
            if (path === forbidden.toLowerCase() || path.startsWith(`${forbidden.toLowerCase()}.`)) {
                return { allowed: false, forbiddenPath: op.path || forbidden };
            }
        }

        // Check for enterprise extension in value object
        if (!op.path && op.value && typeof op.value === 'object') {
            const valueObj = op.value as Record<string, unknown>;
            if (SCIM_ENTERPRISE_USER_SCHEMA in valueObj) {
                return { allowed: false, forbiddenPath: SCIM_ENTERPRISE_USER_SCHEMA };
            }
            for (const forbidden of FORBIDDEN_SELF_UPDATE_PATHS) {
                if (forbidden in valueObj) {
                    return { allowed: false, forbiddenPath: forbidden };
                }
            }
        }
    }

    return { allowed: true };
}

// =============================================================================
// Update Expression Builder
// =============================================================================

interface UpdateParams {
    updateExpression: string;
    expressionAttributeNames: Record<string, string>;
    expressionAttributeValues: Record<string, unknown>;
}

/**
 * Build DynamoDB update expression from allowed PATCH operations.
 */
function buildMeUpdateParams(
    operations: readonly ScimPatchOperation[],
    currentUser: UserItem
): UpdateParams | null {
    const updates: string[] = [];
    const names: Record<string, string> = {};
    const values: Record<string, unknown> = {};
    let valueIndex = 0;

    const now = new Date().toISOString();

    for (const op of operations) {
        if (op.op.toLowerCase() !== 'replace' && op.op.toLowerCase() !== 'add') {
            continue; // Only handle replace and add for /Me
        }

        const path = op.path?.toLowerCase();

        // Handle name updates
        if (path === 'name' && op.value && typeof op.value === 'object') {
            const nameValue = op.value as ScimName;
            const currentProfile = currentUser.profile || {};
            const newProfile = {
                ...currentProfile,
                ...(nameValue.givenName !== undefined && { givenName: nameValue.givenName }),
                ...(nameValue.familyName !== undefined && { familyName: nameValue.familyName }),
            };
            names['#profile'] = 'profile';
            values[`:v${valueIndex}`] = newProfile;
            updates.push(`#profile = :v${valueIndex}`);
            valueIndex++;
        } else if (path === 'name.givenname' || path === 'name.givenName') {
            names['#profile'] = 'profile';
            const currentProfile = currentUser.profile || {};
            values[`:v${valueIndex}`] = { ...currentProfile, givenName: op.value as string };
            updates.push(`#profile = :v${valueIndex}`);
            valueIndex++;
        } else if (path === 'name.familyname' || path === 'name.familyName') {
            names['#profile'] = 'profile';
            const currentProfile = currentUser.profile || {};
            values[`:v${valueIndex}`] = { ...currentProfile, familyName: op.value as string };
            updates.push(`#profile = :v${valueIndex}`);
            valueIndex++;
        } else if (path === 'displayname' || path === 'displayName') {
            // displayName is derived from profile, update profile
            continue;
        } else if (path === 'locale') {
            names['#locale'] = 'locale';
            values[`:v${valueIndex}`] = op.value;
            updates.push(`#locale = :v${valueIndex}`);
            valueIndex++;
        } else if (path === 'timezone' || path === 'zoneinfo') {
            names['#zoneinfo'] = 'zoneinfo';
            values[`:v${valueIndex}`] = op.value;
            updates.push(`#zoneinfo = :v${valueIndex}`);
            valueIndex++;
        } else if (!path && op.value && typeof op.value === 'object') {
            // Handle bulk update without path
            const valueObj = op.value as Record<string, unknown>;
            if (valueObj.name && typeof valueObj.name === 'object') {
                const nameValue = valueObj.name as ScimName;
                const currentProfile = currentUser.profile || {};
                const newProfile = {
                    ...currentProfile,
                    ...(nameValue.givenName !== undefined && { givenName: nameValue.givenName }),
                    ...(nameValue.familyName !== undefined && { familyName: nameValue.familyName }),
                };
                names['#profile'] = 'profile';
                values[`:v${valueIndex}`] = newProfile;
                updates.push(`#profile = :v${valueIndex}`);
                valueIndex++;
            }
            if (valueObj.locale !== undefined) {
                names['#locale'] = 'locale';
                values[`:v${valueIndex}`] = valueObj.locale;
                updates.push(`#locale = :v${valueIndex}`);
                valueIndex++;
            }
            if (valueObj.zoneinfo !== undefined || valueObj.timezone !== undefined) {
                names['#zoneinfo'] = 'zoneinfo';
                values[`:v${valueIndex}`] = valueObj.zoneinfo || valueObj.timezone;
                updates.push(`#zoneinfo = :v${valueIndex}`);
                valueIndex++;
            }
        }
    }

    if (updates.length === 0) {
        return null;
    }

    // Always update updatedAt
    names['#updatedAt'] = 'updatedAt';
    values[':updatedAt'] = now;
    updates.push('#updatedAt = :updatedAt');

    return {
        updateExpression: `SET ${updates.join(', ')}`,
        expressionAttributeNames: names,
        expressionAttributeValues: values,
    };
}
