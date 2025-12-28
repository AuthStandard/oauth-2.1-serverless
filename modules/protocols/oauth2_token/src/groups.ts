/**
 * OAuth 2.1 Token Endpoint - User Group Membership
 *
 * Fetches user's group memberships for RBAC claims injection into access tokens.
 *
 * DynamoDB Query Pattern:
 * - PK: USER#<sub>
 * - SK: begins_with(GROUP#)
 *
 * This enables efficient lookup of all groups a user belongs to,
 * which are then included in the access token 'groups' claim.
 *
 * @module oauth2_token/groups
 * @see RFC 9068 - JWT Profile for OAuth 2.0 Access Tokens
 */

import type { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { QueryCommand } from '@aws-sdk/lib-dynamodb';
import type { UserGroupItem } from '../../../shared_types/group';

// =============================================================================
// Group Membership Query
// =============================================================================

/**
 * Fetch all group names for a user.
 *
 * Queries the USER#<sub> partition for all GROUP# sort keys,
 * extracting the denormalized group names for JWT claims.
 *
 * @param userId - User's sub identifier
 * @param tableName - DynamoDB table name
 * @param client - DynamoDB document client
 * @returns Array of group names (empty if user has no groups)
 */
export async function fetchUserGroups(
    userId: string,
    tableName: string,
    client: DynamoDBDocumentClient
): Promise<string[]> {
    const groups: string[] = [];
    let lastEvaluatedKey: Record<string, unknown> | undefined;

    do {
        const result = await client.send(
            new QueryCommand({
                TableName: tableName,
                KeyConditionExpression: 'PK = :pk AND begins_with(SK, :sk)',
                ExpressionAttributeValues: {
                    ':pk': `USER#${userId}`,
                    ':sk': 'GROUP#',
                },
                ProjectionExpression: 'groupName',
                ExclusiveStartKey: lastEvaluatedKey,
            })
        );

        if (result.Items) {
            for (const item of result.Items) {
                const userGroup = item as Pick<UserGroupItem, 'groupName'>;
                if (userGroup.groupName) {
                    groups.push(userGroup.groupName);
                }
            }
        }

        lastEvaluatedKey = result.LastEvaluatedKey;
    } while (lastEvaluatedKey);

    return groups;
}
