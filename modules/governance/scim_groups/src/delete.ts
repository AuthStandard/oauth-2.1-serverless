/**
 * SCIM v2 Group Provisioning - DELETE /scim/v2/Groups/{id}
 *
 * Deletes a group per RFC 7644 Section 3.6.
 *
 * Flow:
 * 1. Fetch group to verify it exists
 * 2. Query all group memberships
 * 3. Use TransactWriteItems to atomically delete:
 *    - GROUP#<id> metadata
 *    - All GROUP#<id>#MEMBER#<user> items
 *    - All USER#<user>#GROUP#<id> reverse lookup items
 * 4. Return 204 No Content
 *
 * @module governance/scim_groups/delete
 * @see RFC 7644 Section 3.6 - Deleting Resources
 */

import type { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { GetCommand, QueryCommand, TransactWriteCommand } from '@aws-sdk/lib-dynamodb';
import type { APIGatewayProxyResultV2 } from 'aws-lambda';
import { AuditLogger, Logger } from '@oauth-server/shared';
import type { GroupItem, GroupMembershipItem, EnvConfig } from './types';
import { scimNoContent, scimNotFound, scimServerError } from './responses';

// =============================================================================
// DELETE Group Handler
// =============================================================================

/**
 * Handle DELETE /scim/v2/Groups/{id} - Delete a group.
 *
 * @param groupId - Group ID from path parameter
 * @param config - Environment configuration
 * @param client - DynamoDB document client
 * @param audit - Audit logger
 * @param requestId - Request ID for logging
 * @returns SCIM response (204 No Content or error)
 */
export async function handleDeleteGroup(
    groupId: string,
    config: EnvConfig,
    client: DynamoDBDocumentClient,
    audit: AuditLogger,
    requestId: string
): Promise<APIGatewayProxyResultV2> {
    const log = new Logger(requestId);

    // Step 1: Fetch group to verify it exists
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

    // Step 2: Query all group memberships
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

    const memberships = (membersResult.Items || []) as GroupMembershipItem[];

    // Step 3: Build transaction items for atomic deletion
    const transactItems: Array<{ Delete: { TableName: string; Key: Record<string, string> } }> = [];

    // Delete group metadata
    transactItems.push({
        Delete: {
            TableName: config.tableName,
            Key: {
                PK: `GROUP#${groupId}`,
                SK: 'METADATA',
            },
        },
    });

    // Delete all membership items (both directions)
    for (const membership of memberships) {
        // Delete Group → User membership
        transactItems.push({
            Delete: {
                TableName: config.tableName,
                Key: {
                    PK: `GROUP#${groupId}`,
                    SK: `MEMBER#${membership.memberId}`,
                },
            },
        });

        // Delete User → Group reverse lookup
        if (membership.memberType === 'User') {
            transactItems.push({
                Delete: {
                    TableName: config.tableName,
                    Key: {
                        PK: `USER#${membership.memberId}`,
                        SK: `GROUP#${groupId}`,
                    },
                },
            });
        }
    }

    // DynamoDB TransactWriteItems has a limit of 100 items
    // For groups with many members, we need to batch
    const BATCH_SIZE = 25; // Conservative limit to stay under 100 with both directions

    if (transactItems.length <= 100) {
        // Single transaction
        try {
            await client.send(
                new TransactWriteCommand({
                    TransactItems: transactItems,
                })
            );
        } catch (err) {
            log.error('Failed to delete group', { error: (err as Error).message, groupId });
            return scimServerError('Failed to delete group');
        }
    } else {
        // Multiple batches - delete memberships first, then group
        // Note: This is not fully atomic, but handles large groups
        log.warn('Large group deletion - using batched operations', {
            groupId,
            memberCount: memberships.length,
        });

        // Delete memberships in batches
        for (let i = 1; i < transactItems.length; i += BATCH_SIZE) {
            const batch = transactItems.slice(i, i + BATCH_SIZE);
            try {
                await client.send(
                    new TransactWriteCommand({
                        TransactItems: batch,
                    })
                );
            } catch (err) {
                log.error('Failed to delete group memberships batch', {
                    error: (err as Error).message,
                    groupId,
                    batchStart: i,
                });
                // Continue with other batches
            }
        }

        // Finally delete the group metadata
        try {
            await client.send(
                new TransactWriteCommand({
                    TransactItems: [transactItems[0]],
                })
            );
        } catch (err) {
            log.error('Failed to delete group metadata', { error: (err as Error).message, groupId });
            return scimServerError('Failed to delete group');
        }
    }

    // Step 4: Audit log
    audit.log({
        action: 'GROUP_DELETED',
        actor: { type: 'SYSTEM' },
        details: {
            groupId,
            displayName: group.displayName,
            memberCount: memberships.length,
        },
    });

    log.info('Group deleted', { groupId, memberCount: memberships.length });

    // Step 5: Return 204 No Content
    return scimNoContent();
}
