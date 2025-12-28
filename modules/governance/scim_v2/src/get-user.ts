/**
 * SCIM v2 User Provisioning - GET /scim/v2/Users/{id}
 *
 * Retrieves a user by ID per RFC 7644 Section 3.4.1.
 *
 * @module governance/scim_v2/get-user
 * @see RFC 7644 Section 3.4.1 - Retrieving a Known Resource
 */

import type { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { GetCommand } from '@aws-sdk/lib-dynamodb';
import type { APIGatewayProxyResultV2 } from 'aws-lambda';
import type { UserItem } from '../../../shared_types/user';
import type { EnvConfig } from './types';
import { userItemToScimUser } from './mapper';
import { scimUserResponse, scimNotFound } from './responses';

// =============================================================================
// GET User Handler
// =============================================================================

/**
 * Handle GET /scim/v2/Users/{id} - Retrieve a user by ID.
 *
 * @param userId - User ID from path parameter
 * @param config - Environment configuration
 * @param client - DynamoDB document client
 * @returns SCIM response (200 OK or 404 Not Found)
 */
export async function handleGetUser(
    userId: string,
    config: EnvConfig,
    client: DynamoDBDocumentClient
): Promise<APIGatewayProxyResultV2> {
    // Fetch user from DynamoDB
    const result = await client.send(
        new GetCommand({
            TableName: config.tableName,
            Key: { PK: `USER#${userId}`, SK: 'PROFILE' },
        })
    );

    if (!result.Item) {
        return scimNotFound(`User ${userId} not found`);
    }

    const user = result.Item as UserItem;
    const scimUser = userItemToScimUser(user, config);

    return scimUserResponse(scimUser, 200);
}
