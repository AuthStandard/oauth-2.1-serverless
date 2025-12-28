/**
 * SCIM v2 Group Provisioning - Request Validation
 *
 * Validates SCIM requests per RFC 7643 and RFC 7644.
 *
 * @module governance/scim_groups/validation
 * @see RFC 7643 - SCIM Core Schema
 * @see RFC 7644 - SCIM Protocol
 */

import type {
    ScimGroupCreateRequest,
    ScimPatchRequest,
    ScimPatchOperation,
    ScimGroupMember,
} from './types';
import { SCIM_GROUP_SCHEMA, SCIM_PATCH_SCHEMA } from './types';

// =============================================================================
// Validation Result Types
// =============================================================================

export interface ValidationResult {
    readonly valid: boolean;
    readonly error?: string;
}

// =============================================================================
// Group Create Request Validation
// =============================================================================

/**
 * Validate SCIM Group creation request per RFC 7643.
 *
 * Required attributes:
 * - displayName: REQUIRED (RFC 7643 Section 4.2)
 *
 * @param request - SCIM Group creation request
 * @returns Validation result
 */
export function validateGroupCreateRequest(request: ScimGroupCreateRequest): ValidationResult {
    // Validate schemas if provided
    if (request.schemas && request.schemas.length > 0) {
        if (!request.schemas.includes(SCIM_GROUP_SCHEMA)) {
            return {
                valid: false,
                error: `Invalid schema. Expected: ${SCIM_GROUP_SCHEMA}`,
            };
        }
    }

    // displayName is REQUIRED per RFC 7643 Section 4.2
    if (!request.displayName || typeof request.displayName !== 'string') {
        return {
            valid: false,
            error: 'displayName is required',
        };
    }

    if (request.displayName.trim().length === 0) {
        return {
            valid: false,
            error: 'displayName cannot be empty',
        };
    }

    if (request.displayName.length > 256) {
        return {
            valid: false,
            error: 'displayName must not exceed 256 characters',
        };
    }

    // Validate members if provided
    if (request.members) {
        const membersValidation = validateMembers(request.members);
        if (!membersValidation.valid) {
            return membersValidation;
        }
    }

    return { valid: true };
}

// =============================================================================
// Members Validation
// =============================================================================

/**
 * Validate group members array.
 *
 * @param members - Array of group members
 * @returns Validation result
 */
export function validateMembers(members: readonly ScimGroupMember[]): ValidationResult {
    if (!Array.isArray(members)) {
        return {
            valid: false,
            error: 'members must be an array',
        };
    }

    const seenValues = new Set<string>();

    for (let i = 0; i < members.length; i++) {
        const member = members[i];

        // value is REQUIRED for each member
        if (!member.value || typeof member.value !== 'string') {
            return {
                valid: false,
                error: `members[${i}].value is required`,
            };
        }

        if (member.value.trim().length === 0) {
            return {
                valid: false,
                error: `members[${i}].value cannot be empty`,
            };
        }

        // Check for duplicate members
        if (seenValues.has(member.value)) {
            return {
                valid: false,
                error: `Duplicate member value: ${member.value}`,
            };
        }
        seenValues.add(member.value);

        // Validate type if provided
        if (member.type && !['User', 'Group'].includes(member.type)) {
            return {
                valid: false,
                error: `members[${i}].type must be "User" or "Group"`,
            };
        }
    }

    return { valid: true };
}

// =============================================================================
// PATCH Request Validation
// =============================================================================

/**
 * Validate SCIM PATCH request per RFC 7644 Section 3.5.2.
 *
 * @param request - SCIM PATCH request
 * @returns Validation result
 */
export function validatePatchRequest(request: ScimPatchRequest): ValidationResult {
    // Validate schemas
    if (!request.schemas || !request.schemas.includes(SCIM_PATCH_SCHEMA)) {
        return {
            valid: false,
            error: `Invalid schema. Expected: ${SCIM_PATCH_SCHEMA}`,
        };
    }

    // Operations is REQUIRED
    if (!request.Operations || !Array.isArray(request.Operations)) {
        return {
            valid: false,
            error: 'Operations array is required',
        };
    }

    if (request.Operations.length === 0) {
        return {
            valid: false,
            error: 'Operations array cannot be empty',
        };
    }

    // Validate each operation
    for (let i = 0; i < request.Operations.length; i++) {
        const opValidation = validatePatchOperation(request.Operations[i], i);
        if (!opValidation.valid) {
            return opValidation;
        }
    }

    return { valid: true };
}

/**
 * Validate a single PATCH operation.
 *
 * @param operation - SCIM PATCH operation
 * @param index - Operation index for error messages
 * @returns Validation result
 */
function validatePatchOperation(operation: ScimPatchOperation, index: number): ValidationResult {
    // op is REQUIRED
    if (!operation.op || typeof operation.op !== 'string') {
        return {
            valid: false,
            error: `Operations[${index}].op is required`,
        };
    }

    const op = operation.op.toLowerCase();
    if (!['add', 'remove', 'replace'].includes(op)) {
        return {
            valid: false,
            error: `Operations[${index}].op must be "add", "remove", or "replace"`,
        };
    }

    // For add and replace, value is typically required
    if ((op === 'add' || op === 'replace') && operation.value === undefined) {
        // Value can be omitted if path points to a complex attribute
        // For simplicity, we allow it and handle in the handler
    }

    // For remove, path is typically required
    if (op === 'remove' && !operation.path) {
        return {
            valid: false,
            error: `Operations[${index}].path is required for remove operation`,
        };
    }

    return { valid: true };
}

// =============================================================================
// Member Value Extraction
// =============================================================================

/**
 * Extract member values from PATCH operation value.
 *
 * Handles both array format and single object format:
 * - { "value": "user-id" }
 * - [{ "value": "user-id-1" }, { "value": "user-id-2" }]
 *
 * @param value - PATCH operation value
 * @returns Array of member objects or null if invalid
 */
export function extractMemberValues(value: unknown): ScimGroupMember[] | null {
    if (!value) {
        return null;
    }

    // Handle array format
    if (Array.isArray(value)) {
        const members: ScimGroupMember[] = [];
        for (const item of value) {
            if (typeof item === 'object' && item !== null && 'value' in item) {
                members.push(item as ScimGroupMember);
            } else if (typeof item === 'string') {
                // Allow simple string values
                members.push({ value: item });
            } else {
                return null;
            }
        }
        return members;
    }

    // Handle single object format
    if (typeof value === 'object' && value !== null && 'value' in value) {
        return [value as ScimGroupMember];
    }

    // Handle single string format
    if (typeof value === 'string') {
        return [{ value }];
    }

    return null;
}
