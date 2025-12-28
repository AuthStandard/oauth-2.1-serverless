/**
 * SCIM v2 Group Provisioning - Entity Mapper
 *
 * Maps between SCIM Group resources and DynamoDB entities.
 *
 * @module governance/scim_groups/mapper
 */

import type {
    GroupItem,
    GroupMembershipItem,
    UserGroupItem,
    ScimGroup,
    ScimGroupMember,
    ScimGroupMeta,
    EnvConfig,
} from './types';
import { SCIM_GROUP_SCHEMA } from './types';

// =============================================================================
// DynamoDB → SCIM Mapping
// =============================================================================

/**
 * Convert a DynamoDB GroupItem to a SCIM Group resource.
 *
 * @param group - DynamoDB GroupItem
 * @param members - Array of group members (optional)
 * @param config - Environment configuration (for location URI)
 * @returns SCIM Group resource
 */
export function groupItemToScimGroup(
    group: GroupItem,
    members: readonly ScimGroupMember[] | undefined,
    config: EnvConfig
): ScimGroup {
    const meta: ScimGroupMeta = {
        resourceType: 'Group',
        created: group.createdAt,
        lastModified: group.updatedAt,
        location: `${config.scimBaseUrl}/Groups/${group.groupId}`,
    };

    return {
        schemas: [SCIM_GROUP_SCHEMA],
        id: group.groupId,
        externalId: group.externalId,
        displayName: group.displayName,
        members: members && members.length > 0 ? members : undefined,
        meta,
    };
}

/**
 * Convert a GroupMembershipItem to a SCIM GroupMember.
 *
 * @param membership - DynamoDB GroupMembershipItem
 * @param config - Environment configuration (for $ref URI)
 * @returns SCIM GroupMember
 */
export function membershipToScimMember(
    membership: GroupMembershipItem,
    config: EnvConfig
): ScimGroupMember {
    const resourceType = membership.memberType === 'User' ? 'Users' : 'Groups';
    return {
        value: membership.memberId,
        $ref: `${config.scimBaseUrl}/${resourceType}/${membership.memberId}`,
        display: membership.memberDisplay,
        type: membership.memberType,
    };
}

// =============================================================================
// SCIM → DynamoDB Mapping
// =============================================================================

/**
 * Build a DynamoDB GroupItem from SCIM Group creation request.
 *
 * @param params - Group creation parameters
 * @returns GroupItem for DynamoDB
 */
export function buildGroupItem(params: {
    groupId: string;
    displayName: string;
    externalId?: string;
    memberCount: number;
}): GroupItem {
    const now = new Date().toISOString();

    return {
        PK: `GROUP#${params.groupId}`,
        SK: 'METADATA',
        GSI1PK: 'GROUPS',
        GSI1SK: `GROUP#${now}#${params.groupId}`,
        entityType: 'GROUP',
        groupId: params.groupId,
        displayName: params.displayName,
        externalId: params.externalId,
        memberCount: params.memberCount,
        createdAt: now,
        updatedAt: now,
    };
}

/**
 * Build a DynamoDB GroupMembershipItem.
 *
 * @param params - Membership parameters
 * @returns GroupMembershipItem for DynamoDB
 */
export function buildGroupMembershipItem(params: {
    groupId: string;
    memberId: string;
    memberType: 'User' | 'Group';
    memberDisplay?: string;
    memberEmail?: string;
}): GroupMembershipItem {
    const now = new Date().toISOString();

    return {
        PK: `GROUP#${params.groupId}`,
        SK: `MEMBER#${params.memberId}`,
        GSI1PK: `MEMBER#${params.memberId}`,
        GSI1SK: `GROUP#${params.groupId}`,
        entityType: 'GROUP_MEMBERSHIP',
        groupId: params.groupId,
        memberId: params.memberId,
        memberType: params.memberType,
        memberDisplay: params.memberDisplay,
        memberEmail: params.memberEmail,
        addedAt: now,
        createdAt: now,
        updatedAt: now,
    };
}

/**
 * Build a DynamoDB UserGroupItem (reverse lookup).
 *
 * @param params - User group parameters
 * @returns UserGroupItem for DynamoDB
 */
export function buildUserGroupItem(params: {
    userId: string;
    groupId: string;
    groupName: string;
}): UserGroupItem {
    const now = new Date().toISOString();

    return {
        PK: `USER#${params.userId}`,
        SK: `GROUP#${params.groupId}`,
        GSI1PK: `GROUP#${params.groupId}`,
        GSI1SK: `USER#${params.userId}`,
        entityType: 'USER_GROUP',
        userId: params.userId,
        groupId: params.groupId,
        groupName: params.groupName,
        addedAt: now,
        createdAt: now,
        updatedAt: now,
    };
}

// =============================================================================
// Update Expression Builders
// =============================================================================

/**
 * Build update expression for group metadata updates.
 *
 * @param displayName - New display name (optional)
 * @param memberCountDelta - Change in member count
 * @returns DynamoDB update parameters
 */
export function buildGroupUpdateParams(params: {
    displayName?: string;
    memberCountDelta?: number;
}): {
    updateExpression: string;
    expressionAttributeNames: Record<string, string>;
    expressionAttributeValues: Record<string, unknown>;
} {
    const now = new Date().toISOString();
    const setExpressions: string[] = ['updatedAt = :now'];
    const expressionAttributeNames: Record<string, string> = {};
    const expressionAttributeValues: Record<string, unknown> = { ':now': now };

    if (params.displayName !== undefined) {
        setExpressions.push('displayName = :displayName');
        expressionAttributeValues[':displayName'] = params.displayName;
    }

    if (params.memberCountDelta !== undefined) {
        setExpressions.push('memberCount = memberCount + :delta');
        expressionAttributeValues[':delta'] = params.memberCountDelta;
    }

    return {
        updateExpression: `SET ${setExpressions.join(', ')}`,
        expressionAttributeNames,
        expressionAttributeValues,
    };
}
