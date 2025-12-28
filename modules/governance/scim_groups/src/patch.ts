/**
 * SCIM v2 Group Provisioning - PATCH /scim/v2/Groups/{id}
 *
 * Updates a group per RFC 7644 Section 3.5.2.
 *
 * Supported Operations:
 * - replace displayName: Update group name
 * - add members: Add users to group
 * - remove members: Remove users from group
 *
 * @module governance/scim_groups/patch
 * @see RFC 7644 Section 3.5.2 - Modifying with PATCH
 */

import type { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import {
    GetCommand,
    UpdateCommand,
    QueryCommand,
    TransactWriteCommand,
} from '@aws-sdk/lib-dynamodb';
import type { APIGatewayProxyResultV2 } from 'aws-lambda';
import { AuditLogger, Logger } from '@oauth-server/shared';
import type {
    GroupItem,
    GroupMembershipItem,
    ScimPatchRequest,
    EnvConfig,
    ScimGroupMember,
} from './types';
import { validatePatchRequest, extractMemberValues } from './validation';
import {
    groupItemToScimGroup,
    membershipToScimMember,
    buildGroupMembershipItem,
    buildUserGroupItem,
} from './mapper';
import { scimGroupResponse, scimBadRequest, scimNotFound } from './responses';

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
// Member Operations
// =============================================================================

/**
 * Add members to a group using TransactWriteItems.
 */
async function addMembers(
    groupId: string,
    groupName: string,
    members: ScimGroupMember[],
    client: DynamoDBDocumentClient,
    tableName: string,
    scimBaseUrl: string,
    log: Logger
): Promise<{ added: ScimGroupMember[]; notFound: string[] }> {
    const added: ScimGroupMember[] = [];
    const notFound: string[] = [];
    const transactItems: Array<{ Put: { TableName: string; Item: Record<string, unknown> } }> = [];

    for (const member of members) {
        const memberType = member.type || 'User';

        if (memberType === 'User') {
            // Fetch user info for denormalization
            const userInfo = await fetchUserInfo(member.value, client, tableName);
            if (!userInfo) {
                notFound.push(member.value);
                continue;
            }

            // Group → User membership
            const membershipItem = buildGroupMembershipItem({
                groupId,
                memberId: member.value,
                memberType: 'User',
                memberDisplay: userInfo.displayName,
                memberEmail: userInfo.email,
            });

            transactItems.push({
                Put: {
                    TableName: tableName,
                    Item: membershipItem as unknown as Record<string, unknown>,
                },
            });

            // User → Group reverse lookup
            const userGroupItem = buildUserGroupItem({
                userId: member.value,
                groupId,
                groupName,
            });

            transactItems.push({
                Put: {
                    TableName: tableName,
                    Item: userGroupItem as unknown as Record<string, unknown>,
                },
            });

            added.push({
                value: member.value,
                $ref: `${scimBaseUrl}/Users/${member.value}`,
                display: userInfo.displayName,
                type: 'User',
            });
        }
    }

    if (transactItems.length > 0) {
        try {
            await client.send(
                new TransactWriteCommand({
                    TransactItems: transactItems,
                })
            );
        } catch (err) {
            log.error('Failed to add members', { error: (err as Error).message });
            throw err;
        }
    }

    return { added, notFound };
}

/**
 * Remove members from a group using TransactWriteItems.
 */
async function removeMembers(
    groupId: string,
    memberIds: string[],
    client: DynamoDBDocumentClient,
    tableName: string,
    log: Logger
): Promise<number> {
    const transactItems: Array<{ Delete: { TableName: string; Key: Record<string, string> } }> = [];

    for (const memberId of memberIds) {
        // Delete Group → User membership
        transactItems.push({
            Delete: {
                TableName: tableName,
                Key: {
                    PK: `GROUP#${groupId}`,
                    SK: `MEMBER#${memberId}`,
                },
            },
        });

        // Delete User → Group reverse lookup
        transactItems.push({
            Delete: {
                TableName: tableName,
                Key: {
                    PK: `USER#${memberId}`,
                    SK: `GROUP#${groupId}`,
                },
            },
        });
    }

    if (transactItems.length > 0) {
        try {
            await client.send(
                new TransactWriteCommand({
                    TransactItems: transactItems,
                })
            );
        } catch (err) {
            log.error('Failed to remove members', { error: (err as Error).message });
            throw err;
        }
    }

    return memberIds.length;
}

// =============================================================================
// PATCH Group Handler
// =============================================================================

/**
 * Handle PATCH /scim/v2/Groups/{id} - Update a group.
 *
 * @param groupId - Group ID from path parameter
 * @param body - Parsed SCIM PATCH request
 * @param config - Environment configuration
 * @param client - DynamoDB document client
 * @param audit - Audit logger
 * @param requestId - Request ID for logging
 * @returns SCIM response (200 OK or error)
 */
export async function handlePatchGroup(
    groupId: string,
    body: ScimPatchRequest,
    config: EnvConfig,
    client: DynamoDBDocumentClient,
    audit: AuditLogger,
    requestId: string
): Promise<APIGatewayProxyResultV2> {
    const log = new Logger(requestId);

    // Step 1: Validate request
    const validation = validatePatchRequest(body);
    if (!validation.valid) {
        return scimBadRequest(validation.error || 'Invalid request', 'invalidSyntax');
    }

    // Step 2: Fetch existing group
    const groupResult = await client.send(
        new GetCommand({
            TableName: config.tableName,
            Key: { PK: `GROUP#${groupId}`, SK: 'METADATA' },
        })
    );

    if (!groupResult.Item) {
        return scimNotFound(`Group ${groupId} not found`);
    }

    const group = groupResult.Item as GroupItem;
    let memberCountDelta = 0;
    let displayNameUpdated = false;
    let newDisplayName = group.displayName;

    // Step 3: Process operations
    for (const op of body.Operations) {
        const opType = op.op.toLowerCase();
        const path = op.path?.toLowerCase();

        if (opType === 'replace') {
            // Handle displayName replacement
            if (path === 'displayname' || (!path && typeof op.value === 'object' && 'displayName' in (op.value as object))) {
                let displayName: string;
                if (path === 'displayname') {
                    displayName = op.value as string;
                } else {
                    displayName = (op.value as { displayName: string }).displayName;
                }

                if (!displayName || displayName.trim().length === 0) {
                    return scimBadRequest('displayName cannot be empty', 'invalidValue');
                }

                newDisplayName = displayName;
                displayNameUpdated = true;
            } else if (path === 'members') {
                // Replace all members - not implemented for simplicity
                return scimBadRequest('Replace members operation not supported. Use add/remove instead.', 'invalidValue');
            }
        } else if (opType === 'add') {
            // Handle adding members
            if (path === 'members' || path?.startsWith('members')) {
                const memberValues = extractMemberValues(op.value);
                if (!memberValues || memberValues.length === 0) {
                    return scimBadRequest('Invalid members value for add operation', 'invalidValue');
                }

                const result = await addMembers(
                    groupId,
                    newDisplayName,
                    memberValues,
                    client,
                    config.tableName,
                    config.scimBaseUrl,
                    log
                );

                if (result.notFound.length > 0) {
                    return scimNotFound(`Users not found: ${result.notFound.join(', ')}`);
                }

                memberCountDelta += result.added.length;
            }
        } else if (opType === 'remove') {
            // Handle removing members
            if (path === 'members' || path?.startsWith('members')) {
                // Extract member IDs from path or value
                let memberIds: string[] = [];

                // Check for path-based removal: members[value eq "user-id"]
                const filterMatch = path?.match(/members\[value eq "([^"]+)"\]/i);
                if (filterMatch) {
                    memberIds = [filterMatch[1]];
                } else if (op.value) {
                    const memberValues = extractMemberValues(op.value);
                    if (memberValues) {
                        memberIds = memberValues.map(m => m.value);
                    }
                }

                if (memberIds.length === 0) {
                    return scimBadRequest('Invalid members value for remove operation', 'invalidValue');
                }

                const removedCount = await removeMembers(
                    groupId,
                    memberIds,
                    client,
                    config.tableName,
                    log
                );

                memberCountDelta -= removedCount;
            } else {
                return scimBadRequest(`Unsupported path for remove: ${op.path}`, 'invalidPath');
            }
        }
    }

    // Step 4: Update group metadata if needed
    if (displayNameUpdated || memberCountDelta !== 0) {
        const now = new Date().toISOString();
        const updateExpressions: string[] = ['updatedAt = :now'];
        const expressionAttributeValues: Record<string, unknown> = { ':now': now };

        if (displayNameUpdated) {
            updateExpressions.push('displayName = :displayName');
            expressionAttributeValues[':displayName'] = newDisplayName;
        }

        if (memberCountDelta !== 0) {
            updateExpressions.push('memberCount = memberCount + :delta');
            expressionAttributeValues[':delta'] = memberCountDelta;
        }

        try {
            await client.send(
                new UpdateCommand({
                    TableName: config.tableName,
                    Key: { PK: `GROUP#${groupId}`, SK: 'METADATA' },
                    UpdateExpression: `SET ${updateExpressions.join(', ')}`,
                    ExpressionAttributeValues: expressionAttributeValues,
                    ConditionExpression: 'attribute_exists(PK)',
                })
            );
        } catch (err) {
            if ((err as Error).name === 'ConditionalCheckFailedException') {
                return scimNotFound(`Group ${groupId} not found`);
            }
            throw err;
        }

        // Update local group object for response
        group.displayName = newDisplayName;
        group.updatedAt = now;
        group.memberCount = Math.max(0, group.memberCount + memberCountDelta);
    }

    // Step 5: Fetch current members for response
    const membersResult = await client.send(
        new QueryCommand({
            TableName: config.tableName,
            KeyConditionExpression: 'PK = :pk AND begins_with(SK, :sk)',
            ExpressionAttributeValues: {
                ':pk': `GROUP#${groupId}`,
                ':sk': 'MEMBER#',
            },
        })
    );

    const members: ScimGroupMember[] = [];
    if (membersResult.Items && membersResult.Items.length > 0) {
        for (const item of membersResult.Items) {
            const membership = item as GroupMembershipItem;
            members.push(membershipToScimMember(membership, config));
        }
    }

    // Step 6: Audit log
    audit.log({
        action: 'GROUP_UPDATED',
        actor: { type: 'SYSTEM' },
        details: {
            groupId,
            displayName: newDisplayName,
            memberCountDelta,
            operations: body.Operations.map(op => op.op),
        },
    });

    // Step 7: Return updated group
    const scimGroup = groupItemToScimGroup(group, members.length > 0 ? members : undefined, config);
    return scimGroupResponse(scimGroup, 200);
}
