/**
 * SCIM v2 Group Provisioning - GET /scim/v2/Groups/{id}
 *
 * Retrieves a group by ID per RFC 7644 Section 3.4.1.
 *
 * @module governance/scim_groups/get
 * @see RFC 7644 Section 3.4.1 - Retrieving a Known Resource
 */

import type { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { GetCommand, QueryCommand } from '@aws-sdk/lib-dynamodb';
import type { APIGatewayProxyResultV2 } from 'aws-lambda';
import type { GroupItem, GroupMembershipItem, EnvConfig, ScimGroupMember } from './types';
import { groupItemToScimGroup, membershipToScimMember } from './mapper';
import { scimGroupResponse, scimNotFound } from './responses';

// =============================================================================
// GET Group Handler
// =============================================================================

/**
 * Handle GET /scim/v2/Groups/{id} - Retrieve a group by ID.
 *
 * @param groupId - Group ID from path parameter
 * @param config - Environment configuration
 * @param client - DynamoDB document client
 * @returns SCIM response (200 OK or 404 Not Found)
 */
export async function handleGetGroup(
    groupId: string,
    config: EnvConfig,
    client: DynamoDBDocumentClient
): Promise<APIGatewayProxyResultV2> {
    // Fetch group metadata
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

    // Fetch group members
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

    const scimGroup = groupItemToScimGroup(group, members.length > 0 ? members : undefined, config);
    return scimGroupResponse(scimGroup, 200);
}

// =============================================================================
// List Groups Handler
// =============================================================================

/**
 * Handle GET /scim/v2/Groups - List all groups.
 *
 * @param config - Environment configuration
 * @param client - DynamoDB document client
 * @param startIndex - Starting index (1-based, default 1)
 * @param count - Maximum number of results (default 100)
 * @returns SCIM ListResponse
 */
export async function handleListGroups(
    config: EnvConfig,
    client: DynamoDBDocumentClient,
    startIndex: number = 1,
    count: number = 100
): Promise<APIGatewayProxyResultV2> {
    // Query all groups using GSI1
    const result = await client.send(
        new QueryCommand({
            TableName: config.tableName,
            IndexName: 'GSI1',
            KeyConditionExpression: 'GSI1PK = :pk',
            ExpressionAttributeValues: {
                ':pk': 'GROUPS',
            },
            Limit: count,
        })
    );

    const groups = result.Items as GroupItem[] || [];

    // Convert to SCIM format (without members for list response)
    const scimGroups = groups.map(group =>
        groupItemToScimGroup(group, undefined, config)
    );

    // Build list response
    const response = {
        schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse' as const],
        totalResults: scimGroups.length,
        startIndex,
        itemsPerPage: scimGroups.length,
        Resources: scimGroups,
    };

    return {
        statusCode: 200,
        headers: {
            'Content-Type': 'application/scim+json;charset=UTF-8',
            'Cache-Control': 'no-store',
        },
        body: JSON.stringify(response),
    };
}
