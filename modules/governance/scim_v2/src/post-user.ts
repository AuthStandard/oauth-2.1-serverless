/**
 * SCIM v2 User Provisioning - POST /scim/v2/Users
 *
 * Creates a new user per RFC 7644 Section 3.3.
 *
 * Flow:
 * 1. Parse and validate SCIM User request
 * 2. Check if email already exists (using GSI1)
 * 3. Generate UUID for user sub
 * 4. Hash password with Argon2id if provided
 * 5. Save user profile to USER#<sub>
 * 6. If password provided, save credential to USER#<sub>#CRED#PASSWORD
 * 7. Return SCIM 2.0 response with 201 Created
 *
 * @module governance/scim_v2/post-user
 * @see RFC 7644 Section 3.3 - Creating Resources
 */

import type { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { PutCommand, QueryCommand } from '@aws-sdk/lib-dynamodb';
import type { APIGatewayProxyResultV2 } from 'aws-lambda';
import { randomUUID } from 'node:crypto';
import { argon2id } from 'hash-wasm';
import { AuditLogger } from '@oauth-server/shared';
import type { ScimUserCreateRequest, EnvConfig } from './types';
import { validateUserCreateRequest, extractPrimaryEmail } from './validation';
import { buildUserItem, userItemToScimUser } from './mapper';
import { scimUserResponse, scimBadRequest, scimConflict, scimServerError } from './responses';

// =============================================================================
// Argon2id Configuration (OWASP Recommendations)
// =============================================================================

/**
 * Argon2id parameters per OWASP Password Storage Cheat Sheet.
 * These provide strong protection against GPU-based attacks.
 */
const ARGON2_CONFIG = {
    parallelism: 1,
    iterations: 3,
    memorySize: 65536, // 64 MB
    hashLength: 32,
    outputType: 'encoded' as const,
};

// =============================================================================
// POST User Handler
// =============================================================================

/**
 * Handle POST /scim/v2/Users - Create a new user.
 *
 * @param body - Parsed SCIM User creation request
 * @param config - Environment configuration
 * @param client - DynamoDB document client
 * @param audit - Audit logger
 * @returns SCIM response (201 Created or error)
 */
export async function handlePostUser(
    body: ScimUserCreateRequest,
    config: EnvConfig,
    client: DynamoDBDocumentClient,
    audit: AuditLogger
): Promise<APIGatewayProxyResultV2> {
    // Step 1: Validate request
    const validation = validateUserCreateRequest(body);
    if (!validation.valid) {
        return scimBadRequest(validation.error || 'Invalid request', 'invalidValue');
    }

    // Step 2: Determine email (from emails array or userName)
    const email = extractPrimaryEmail(body.emails) || body.userName;

    // Validate email format
    if (!email.includes('@')) {
        return scimBadRequest('userName must be a valid email address', 'invalidValue');
    }

    const emailNormalized = email.toLowerCase();

    // Step 3: Check if email already exists (using GSI1)
    const existingUser = await client.send(
        new QueryCommand({
            TableName: config.tableName,
            IndexName: 'GSI1',
            KeyConditionExpression: 'GSI1PK = :pk AND GSI1SK = :sk',
            ExpressionAttributeValues: {
                ':pk': `EMAIL#${emailNormalized}`,
                ':sk': 'USER',
            },
            Limit: 1,
        })
    );

    if (existingUser.Items && existingUser.Items.length > 0) {
        return scimConflict(`User with email ${email} already exists`);
    }

    // Step 4: Generate UUID for user sub
    const sub = randomUUID();

    // Step 5: Hash password if provided
    let passwordHash: string | undefined;
    if (body.password) {
        try {
            passwordHash = await argon2id({
                password: body.password,
                salt: Buffer.from(randomUUID().replace(/-/g, ''), 'hex'),
                ...ARGON2_CONFIG,
            });
        } catch {
            // Password hashing failed - log and return error
            return scimServerError('Failed to process password');
        }
    }

    // Step 6: Build and save user item (including enterprise extension)
    const enterpriseExt = body['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'];
    const userItem = buildUserItem({
        sub,
        userName: body.userName,
        email: emailNormalized,
        name: body.name,
        active: body.active !== false, // Default to true
        passwordHash,
        enterprise: enterpriseExt,
    });

    try {
        await client.send(
            new PutCommand({
                TableName: config.tableName,
                Item: userItem,
                // Ensure user doesn't already exist (race condition protection)
                ConditionExpression: 'attribute_not_exists(PK)',
            })
        );
    } catch (err) {
        if ((err as Error).name === 'ConditionalCheckFailedException') {
            return scimConflict(`User with email ${email} already exists`);
        }
        throw err;
    }

    // Step 7: Audit log
    audit.log({
        action: 'USER_PROVISIONED',
        actor: { type: 'SYSTEM' },
        details: {
            sub,
            email: emailNormalized,
            hasPassword: !!passwordHash,
            active: userItem.status === 'ACTIVE',
            hasEnterpriseExtension: !!enterpriseExt,
        },
    });

    // Step 8: Return SCIM response
    const scimUser = userItemToScimUser(userItem, config);
    return scimUserResponse(scimUser, 201);
}
