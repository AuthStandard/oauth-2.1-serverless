/**
 * SCIM v2 User Provisioning - Entity Mapper
 *
 * Maps between SCIM User resources and DynamoDB UserItem entities.
 *
 * @module governance/scim_v2/mapper
 */

import type { UserItem, UserProfile, UserStatus } from '../../../shared_types/user';
import type { ScimUser, ScimEmail, ScimName, ScimMeta, EnvConfig, ScimEnterpriseUserExtension } from './types';
import { SCIM_USER_SCHEMA, SCIM_ENTERPRISE_USER_SCHEMA } from './types';

// =============================================================================
// Enterprise Extension Types (for DynamoDB storage)
// =============================================================================

/**
 * Enterprise extension fields stored in DynamoDB UserItem.
 */
export interface EnterpriseFields {
    employeeNumber?: string;
    costCenter?: string;
    organization?: string;
    division?: string;
    department?: string;
    managerId?: string;
    managerDisplayName?: string;
}

// =============================================================================
// Extended UserItem with Enterprise Fields
// =============================================================================

/**
 * UserItem extended with enterprise extension fields.
 */
export interface UserItemWithEnterprise extends UserItem {
    employeeNumber?: string;
    costCenter?: string;
    organization?: string;
    division?: string;
    department?: string;
    managerId?: string;
    managerDisplayName?: string;
}

// =============================================================================
// DynamoDB → SCIM Mapping
// =============================================================================

/**
 * Convert a DynamoDB UserItem to a SCIM User resource.
 *
 * @param user - DynamoDB UserItem (may include enterprise fields)
 * @param config - Environment configuration (for location URI)
 * @returns SCIM User resource
 */
export function userItemToScimUser(user: UserItem | UserItemWithEnterprise, config: EnvConfig): ScimUser {
    const meta: ScimMeta = {
        resourceType: 'User',
        created: user.createdAt,
        lastModified: user.updatedAt,
        location: `${config.scimBaseUrl}/Users/${user.sub}`,
    };

    const emails: ScimEmail[] = [
        {
            value: user.email,
            type: 'work',
            primary: true,
        },
    ];

    const name: ScimName | undefined = user.profile
        ? {
              givenName: user.profile.givenName,
              familyName: user.profile.familyName,
              formatted: formatFullName(user.profile),
          }
        : undefined;

    const displayName = user.profile
        ? formatFullName(user.profile) || user.email
        : user.email;

    // Build enterprise extension if any enterprise fields exist
    const enterpriseExt = buildEnterpriseExtensionFromUser(user as UserItemWithEnterprise, config);
    const schemas: string[] = [SCIM_USER_SCHEMA];
    if (enterpriseExt) {
        schemas.push(SCIM_ENTERPRISE_USER_SCHEMA);
    }

    const scimUser: ScimUser & { 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'?: ScimEnterpriseUserExtension } = {
        schemas,
        id: user.sub,
        userName: user.email,
        name,
        displayName,
        emails,
        active: user.status === 'ACTIVE',
        meta,
    };

    if (enterpriseExt) {
        scimUser['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'] = enterpriseExt;
    }

    return scimUser as ScimUser;
}

/**
 * Build enterprise extension from DynamoDB user fields.
 */
function buildEnterpriseExtensionFromUser(
    user: UserItemWithEnterprise,
    config: EnvConfig
): ScimEnterpriseUserExtension | undefined {
    const hasEnterpriseData =
        user.employeeNumber ||
        user.costCenter ||
        user.organization ||
        user.division ||
        user.department ||
        user.managerId;

    if (!hasEnterpriseData) {
        return undefined;
    }

    const manager = user.managerId
        ? {
              value: user.managerId,
              $ref: `${config.scimBaseUrl}/Users/${user.managerId}`,
              ...(user.managerDisplayName && { displayName: user.managerDisplayName }),
          }
        : undefined;

    return {
        ...(user.employeeNumber && { employeeNumber: user.employeeNumber }),
        ...(user.costCenter && { costCenter: user.costCenter }),
        ...(user.organization && { organization: user.organization }),
        ...(user.division && { division: user.division }),
        ...(user.department && { department: user.department }),
        ...(manager && { manager }),
    };
}

/**
 * Format full name from profile components.
 */
function formatFullName(profile: UserProfile): string | undefined {
    const parts = [profile.givenName, profile.familyName].filter(Boolean);
    return parts.length > 0 ? parts.join(' ') : undefined;
}

// =============================================================================
// SCIM → DynamoDB Mapping
// =============================================================================

/**
 * Build a DynamoDB UserItem from SCIM User creation request.
 *
 * @param params - User creation parameters including enterprise extension
 * @returns UserItem for DynamoDB (with enterprise fields if provided)
 */
export function buildUserItem(params: {
    sub: string;
    userName: string;
    email: string;
    name?: ScimName;
    active: boolean;
    passwordHash?: string;
    enterprise?: ScimEnterpriseUserExtension;
}): UserItemWithEnterprise {
    const now = new Date().toISOString();
    const status: UserStatus = params.active ? 'ACTIVE' : 'SUSPENDED';

    const profile: UserProfile = {
        givenName: params.name?.givenName,
        familyName: params.name?.familyName,
    };

    // Extract enterprise fields
    const enterpriseFields: EnterpriseFields = params.enterprise
        ? {
              ...(params.enterprise.employeeNumber && { employeeNumber: params.enterprise.employeeNumber }),
              ...(params.enterprise.costCenter && { costCenter: params.enterprise.costCenter }),
              ...(params.enterprise.organization && { organization: params.enterprise.organization }),
              ...(params.enterprise.division && { division: params.enterprise.division }),
              ...(params.enterprise.department && { department: params.enterprise.department }),
              ...(params.enterprise.manager?.value && { managerId: params.enterprise.manager.value }),
              ...(params.enterprise.manager?.displayName && { managerDisplayName: params.enterprise.manager.displayName }),
          }
        : {};

    return {
        PK: `USER#${params.sub}`,
        SK: 'PROFILE',
        GSI1PK: `EMAIL#${params.email.toLowerCase()}`,
        GSI1SK: 'USER',
        entityType: 'USER',
        sub: params.sub,
        email: params.email.toLowerCase(),
        emailVerified: false,
        zoneinfo: 'UTC',
        profile,
        status,
        createdAt: now,
        updatedAt: now,
        ...(params.passwordHash && { passwordHash: params.passwordHash }),
        ...enterpriseFields,
    };
}

/**
 * Build update expression for SCIM PATCH operations.
 *
 * @param active - New active status
 * @returns DynamoDB update parameters
 */
export function buildStatusUpdateParams(active: boolean): {
    updateExpression: string;
    expressionAttributeNames: Record<string, string>;
    expressionAttributeValues: Record<string, unknown>;
} {
    const status: UserStatus = active ? 'ACTIVE' : 'SUSPENDED';
    const now = new Date().toISOString();

    return {
        updateExpression: 'SET #status = :status, updatedAt = :now',
        expressionAttributeNames: {
            '#status': 'status',
        },
        expressionAttributeValues: {
            ':status': status,
            ':now': now,
        },
    };
}
