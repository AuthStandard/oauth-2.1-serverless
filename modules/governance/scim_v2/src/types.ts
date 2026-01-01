/**
 * SCIM v2 User Provisioning - Type Definitions
 *
 * Implements SCIM 2.0 (RFC 7643, RFC 7644) User Resource types.
 *
 * @module governance/scim_v2/types
 * @see RFC 7643 - SCIM Core Schema
 * @see RFC 7644 - SCIM Protocol
 */

// =============================================================================
// Environment Configuration
// =============================================================================

/**
 * Runtime configuration from Lambda environment variables.
 * All values originate from Terraform - no hardcoded defaults.
 */
export interface EnvConfig {
    /** DynamoDB table name */
    readonly tableName: string;
    /** OAuth issuer URL (used for SCIM location URIs) */
    readonly issuer: string;
    /** SCIM base URL (derived from issuer) */
    readonly scimBaseUrl: string;
    /** KMS key ID for JWT signature verification */
    readonly kmsKeyId: string;
}

// =============================================================================
// SCIM 2.0 Core Schema Types (RFC 7643)
// =============================================================================

/**
 * SCIM Multi-Valued Attribute (RFC 7643 Section 2.4).
 */
export interface ScimMultiValuedAttribute {
    /** The attribute value */
    readonly value: string;
    /** Display name for the value */
    readonly display?: string;
    /** Canonical type (e.g., "work", "home") */
    readonly type?: string;
    /** Indicates if this is the primary value */
    readonly primary?: boolean;
}

/**
 * SCIM Email attribute (RFC 7643 Section 4.1.2).
 */
export interface ScimEmail extends ScimMultiValuedAttribute {
    readonly type?: 'work' | 'home' | 'other';
}

/**
 * SCIM Name attribute (RFC 7643 Section 4.1.1).
 */
export interface ScimName {
    /** Full name including all middle names, titles, and suffixes */
    readonly formatted?: string;
    /** Family name (last name) */
    readonly familyName?: string;
    /** Given name (first name) */
    readonly givenName?: string;
    /** Middle name(s) */
    readonly middleName?: string;
    /** Honorific prefix (e.g., "Ms.", "Dr.") */
    readonly honorificPrefix?: string;
    /** Honorific suffix (e.g., "Jr.", "III") */
    readonly honorificSuffix?: string;
}

/**
 * SCIM Meta attribute (RFC 7643 Section 3.1).
 */
export interface ScimMeta {
    /** Resource type (always "User" for user resources) */
    readonly resourceType: 'User';
    /** Date and time the resource was created (ISO 8601) */
    readonly created: string;
    /** Date and time the resource was last modified (ISO 8601) */
    readonly lastModified: string;
    /** URI of the resource */
    readonly location: string;
    /** Version of the resource (ETag) */
    readonly version?: string;
}

// =============================================================================
// SCIM 2.0 User Resource (RFC 7643 Section 4.1)
// =============================================================================

/**
 * SCIM User Resource (RFC 7643 Section 4.1).
 *
 * Core attributes for user provisioning.
 */
export interface ScimUser {
    /** SCIM schema URIs */
    readonly schemas: readonly string[];
    /** Unique identifier (maps to DynamoDB sub) */
    readonly id: string;
    /** External identifier from provisioning client */
    readonly externalId?: string;
    /** Unique identifier for authentication (typically email) */
    readonly userName: string;
    /** User's name components */
    readonly name?: ScimName;
    /** Display name */
    readonly displayName?: string;
    /** User's email addresses */
    readonly emails?: readonly ScimEmail[];
    /** User's active status */
    readonly active: boolean;
    /** Resource metadata */
    readonly meta: ScimMeta;
}

/**
 * SCIM User creation request.
 */
export interface ScimUserCreateRequest {
    /** SCIM schema URIs */
    readonly schemas?: readonly string[];
    /** External identifier from provisioning client */
    readonly externalId?: string;
    /** Unique identifier for authentication (typically email) */
    readonly userName: string;
    /** User's name components */
    readonly name?: ScimName;
    /** Display name */
    readonly displayName?: string;
    /** User's email addresses */
    readonly emails?: readonly ScimEmail[];
    /** User's active status (defaults to true) */
    readonly active?: boolean;
    /** Password (optional, for password-based auth) */
    readonly password?: string;
    /** Enterprise User Extension (RFC 7643 Section 4.3) */
    readonly 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'?: ScimEnterpriseUserExtension;
}

/**
 * Enterprise User Extension attributes per RFC 7643 Section 4.3.
 */
export interface ScimEnterpriseUserExtension {
    /** Unique identifier assigned by the organization */
    readonly employeeNumber?: string;
    /** Cost center for accounting purposes */
    readonly costCenter?: string;
    /** Name of the organization */
    readonly organization?: string;
    /** Division within the organization */
    readonly division?: string;
    /** Department within the organization */
    readonly department?: string;
    /** Reference to the user's manager */
    readonly manager?: {
        readonly value?: string;
        readonly $ref?: string;
        readonly displayName?: string;
    };
}

// =============================================================================
// SCIM 2.0 PATCH Operation (RFC 7644 Section 3.5.2)
// =============================================================================

/**
 * SCIM PATCH operation types.
 */
export type ScimPatchOp = 'add' | 'remove' | 'replace';

/**
 * SCIM PATCH operation (RFC 7644 Section 3.5.2).
 */
export interface ScimPatchOperation {
    /** Operation type */
    readonly op: ScimPatchOp;
    /** Attribute path (e.g., "active", "name.givenName") */
    readonly path?: string;
    /** Value to set (for add/replace operations) */
    readonly value?: unknown;
}

/**
 * SCIM PATCH request body.
 */
export interface ScimPatchRequest {
    /** SCIM schema URIs (must include PatchOp schema) */
    readonly schemas: readonly string[];
    /** Array of patch operations */
    readonly Operations: readonly ScimPatchOperation[];
}

// =============================================================================
// SCIM 2.0 Error Response (RFC 7644 Section 3.12)
// =============================================================================

/**
 * SCIM error types (RFC 7644 Section 3.12).
 */
export type ScimErrorType =
    | 'invalidFilter'
    | 'tooMany'
    | 'uniqueness'
    | 'mutability'
    | 'invalidSyntax'
    | 'invalidPath'
    | 'noTarget'
    | 'invalidValue'
    | 'invalidVers'
    | 'sensitive';

/**
 * SCIM error response (RFC 7644 Section 3.12).
 */
export interface ScimErrorResponse {
    /** SCIM schema URIs */
    readonly schemas: readonly ['urn:ietf:params:scim:api:messages:2.0:Error'];
    /** HTTP status code */
    readonly status: string;
    /** SCIM error type */
    readonly scimType?: ScimErrorType;
    /** Human-readable error detail */
    readonly detail?: string;
}

// =============================================================================
// SCIM 2.0 List Response (RFC 7644 Section 3.4.2)
// =============================================================================

/**
 * SCIM List Response (RFC 7644 Section 3.4.2).
 */
export interface ScimListResponse<T> {
    /** SCIM schema URIs */
    readonly schemas: readonly ['urn:ietf:params:scim:api:messages:2.0:ListResponse'];
    /** Total number of results */
    readonly totalResults: number;
    /** Starting index (1-based) */
    readonly startIndex: number;
    /** Number of results per page */
    readonly itemsPerPage: number;
    /** Array of resources */
    readonly Resources: readonly T[];
}

// =============================================================================
// Constants
// =============================================================================

/** SCIM 2.0 User schema URI */
export const SCIM_USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';

/** SCIM 2.0 Error schema URI */
export const SCIM_ERROR_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error';

/** SCIM 2.0 PatchOp schema URI */
export const SCIM_PATCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';

/** SCIM 2.0 ListResponse schema URI */
export const SCIM_LIST_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';

/** SCIM 2.0 Enterprise User Extension schema URI */
export const SCIM_ENTERPRISE_USER_SCHEMA = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';
