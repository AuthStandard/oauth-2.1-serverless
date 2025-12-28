/**
 * SCIM v2 Group Provisioning - POST /scim/v2/Groups
 *
 * Creates a new group per RFC 7644 Section 3.3.
 *
 * Flow:
 * 1. Parse and validate SCIM Group request
 * 2. Generate UUID for group
 * 3. If members provided, fetch user details for denormalization
 * 4. Use TransactWriteItems to atomically:
 *    - Create GROUP#<id> metadata
 *    - Create GROUP#<id>#MEMBER#<user> for each member
 *    - Create USER#<user>#GROUP#<id> for each member (reverse lookup)
 * 5. Return SCIM 2.0 response with 201 Created
 *
 * @module governance/scim_groups/create
 * @see RFC 7644 Section 3.3 - Creating Resources
 */

import type { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { PutCommand, GetCommand, TransactWriteCommand } from '@aws-sdk/lib-dynamodb';
import type { APIGatewayProxyResultV2 } from 'aws-lambda';
import { randomUUID } from 'node:crypto';
import { AuditLogger } from '@oauth-server/shared';
import type { ScimGroupCreateRequest, EnvConfig, ScimGroupMember } from './types';
import { validateGroupCreateRequest } from './validation';
import {
    buildGroupItem,
    buildGroupMembershipItem,
    buildUserGroupItem,
    groupItemToScimGroup,
} from './mapper';
import { scimGroupResponse, scimBadRequest, scimServerError, scimNotFound } from './responses';

// =============================================================================
// User Lookup for Denormalization
// =============================================================================

interface UserInfo {
    sub: string;
    email?: string;
    displayName?: string;
}

/**
 * Fetch user information for denormalization into membership records.
 *
 * @param userId - User's sub identifier
 * @param client - DynamoDB document client
 * @param tableName - DynamoDB table name
 * @returns User info or null if not found
 */
async function fetchUserInfo(
    userId: string,
    client: DynamoDBDocumentClient,
    tableName: string
): Promise<UserInfo | null> {
    const result = await client.send(
        new GetCommand({
            TableName: tableName,
            Key: { PK: `USER#${userId}`, SK: 'PROFILE' },
            ProjectionExpression: '#sub, email, #profile',
            ExpressionAttributeNames: {
                '#sub': 'sub',
                '#profile': 'profile',
            },
        })
    );

    if (!result.Item) {
        return null;
    }

    const profile = result.Item.profile as { givenName?: string; familyName?: string } | undefined;
    const displayName = profile
        ? [profile.givenName, profile.familyName].filter(Boolean).join(' ')
        : undefined;

    return {
        sub: result.Item.sub as string,
        email: result.Item.email as string | undefined,
        displayName: displayName || undefined,
    };
}

// =============================================================================
// POST Group Handler
// =============================================================================

/**
 * Handle POST /scim/v2/Groups - Create a new group.
 *
 * @param body - Parsed SCIM Group creation request
 * @param config - Environment configuration
 * @param client - DynamoDB document client
 * @param audit - Audit logger
 * @returns SCIM response (201 Created or error)
 */
export async function handlePostGroup(
    body: ScimGroupCreateRequest,
    config: EnvConfig,
    client: DynamoDBDocumentClient,
    audit: AuditLogger
): Promise<APIGatewayProxyResultV2> {
    // Step 1: Validate request
    const validation = validateGroupCreateRequest(body);
    if (!validation.valid) {
        return scimBadRequest(validation.error || 'Invalid request', 'invalidValue');
    }

    // Step 2: Generate UUID for group
    const groupId = randomUUID();
    const members = body.members || [];

    // Step 3: Fetch user details for denormalization (if members provided)
    const memberInfos: Map<string, UserInfo> = new Map();
    const notFoundMembers: string[] = [];

    for (const member of members) {
        // Default to User type if not specified
        const memberType = member.type || 'User';

        if (memberType === 'User') {
            const userInfo = await fetchUserInfo(member.value, client, config.tableName);
            if (userInfo) {
                memberInfos.set(member.value, userInfo);
            } else {
                notFoundMembers.push(member.value);
            }
        }
        // For Group type members, we'd need to verify the group exists
        // For now, we only support User members
    }

    // Return error if any members not found
    if (notFoundMembers.length > 0) {
        return scimNotFound(`Users not found: ${notFoundMembers.join(', ')}`);
    }

    // Step 4: Build transaction items
    const groupItem = buildGroupItem({
        groupId,
        displayName: body.displayName,
        externalId: body.externalId,
        memberCount: members.length,
    });

    // If no members, just create the group
    if (members.length === 0) {
        try {
            await client.send(
                new PutCommand({
                    TableName: config.tableName,
                    Item: groupItem,
                    ConditionExpression: 'attribute_not_exists(PK)',
                })
            );
        } catch (err) {
            if ((err as Error).name === 'ConditionalCheckFailedException') {
                return scimServerError('Group creation failed - please retry');
            }
            throw err;
        }

        // Audit log
        audit.log({
            action: 'GROUP_CREATED',
            actor: { type: 'SYSTEM' },
            details: {
                groupId,
                displayName: body.displayName,
                memberCount: 0,
            },
        });

        // Return SCIM response
        const scimGroup = groupItemToScimGroup(groupItem, undefined, config);
        return scimGroupResponse(scimGroup, 201);
    }

    // Step 5: Use TransactWriteItems for atomic creation with members
    const transactItems: Array<{
        Put: {
            TableName: string;
            Item: Record<string, unknown>;
            ConditionExpression?: string;
        };
    }> = [];

    // Add group metadata
    transactItems.push({
        Put: {
            TableName: config.tableName,
            Item: groupItem as unknown as Record<string, unknown>,
            ConditionExpression: 'attribute_not_exists(PK)',
        },
    });

    // Add membership items (both directions)
    const scimMembers: ScimGroupMember[] = [];

    for (const member of members) {
        const memberType = member.type || 'User';
        const userInfo = memberInfos.get(member.value);

        // Group → User membership
        const membershipItem = buildGroupMembershipItem({
            groupId,
            memberId: member.value,
            memberType,
            memberDisplay: userInfo?.displayName || member.display,
            memberEmail: userInfo?.email,
        });

        transactItems.push({
            Put: {
                TableName: config.tableName,
                Item: membershipItem as unknown as Record<string, unknown>,
            },
        });

        // User → Group reverse lookup (for JWT claims)
        if (memberType === 'User') {
            const userGroupItem = buildUserGroupItem({
                userId: member.value,
                groupId,
                groupName: body.displayName,
            });

            transactItems.push({
                Put: {
                    TableName: config.tableName,
                    Item: userGroupItem as unknown as Record<string, unknown>,
                },
            });
        }

        // Build SCIM member for response
        scimMembers.push({
            value: member.value,
            $ref: `${config.scimBaseUrl}/Users/${member.value}`,
            display: userInfo?.displayName || member.display,
            type: memberType,
        });
    }

    // Execute transaction
    try {
        await client.send(
            new TransactWriteCommand({
                TransactItems: transactItems,
            })
        );
    } catch (err) {
        const error = err as Error;
        if (error.name === 'TransactionCanceledException') {
            return scimServerError('Group creation failed - please retry');
        }
        throw err;
    }

    // Step 6: Audit log
    audit.log({
        action: 'GROUP_CREATED',
        actor: { type: 'SYSTEM' },
        details: {
            groupId,
            displayName: body.displayName,
            memberCount: members.length,
            memberIds: members.map(m => m.value),
        },
    });

    // Step 7: Return SCIM response
    const scimGroup = groupItemToScimGroup(groupItem, scimMembers, config);
    return scimGroupResponse(scimGroup, 201);
}
