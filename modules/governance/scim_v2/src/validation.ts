/**
 * SCIM v2 User Provisioning - Request Validation
 *
 * Validates SCIM requests per RFC 7643 and RFC 7644.
 *
 * @module governance/scim_v2/validation
 * @see RFC 7643 - SCIM Core Schema
 * @see RFC 7644 - SCIM Protocol
 */

import type {
    ScimUserCreateRequest,
    ScimPatchRequest,
    ScimPatchOperation,
    ScimEmail,
} from './types';
import { SCIM_USER_SCHEMA, SCIM_PATCH_SCHEMA, SCIM_ENTERPRISE_USER_SCHEMA } from './types';

// =============================================================================
// Validation Result Types
// =============================================================================

export interface ValidationResult {
    readonly valid: boolean;
    readonly error?: string;
}

// =============================================================================
// Email Validation
// =============================================================================

/**
 * Basic email format validation.
 */
function isValidEmail(email: string): boolean {
    // RFC 5322 simplified pattern
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email) && email.length <= 254;
}

// =============================================================================
// User Create Request Validation
// =============================================================================

/**
 * Validate SCIM User creation request per RFC 7643.
 *
 * Required attributes:
 * - userName: REQUIRED (RFC 7643 Section 4.1.1)
 *
 * @param request - SCIM User creation request
 * @returns Validation result
 */
export function validateUserCreateRequest(request: ScimUserCreateRequest): ValidationResult {
    // Validate schemas if provided
    if (request.schemas && request.schemas.length > 0) {
        const validSchemas = [SCIM_USER_SCHEMA, SCIM_ENTERPRISE_USER_SCHEMA];
        for (const schema of request.schemas) {
            if (!validSchemas.includes(schema)) {
                return {
                    valid: false,
                    error: `Invalid schema: ${schema}. Expected one of: ${validSchemas.join(', ')}`,
                };
            }
        }
    }

    // userName is REQUIRED per RFC 7643 Section 4.1.1
    if (!request.userName || typeof request.userName !== 'string') {
        return {
            valid: false,
            error: 'userName is required',
        };
    }

    if (request.userName.trim().length === 0) {
        return {
            valid: false,
            error: 'userName cannot be empty',
        };
    }

    if (request.userName.length > 256) {
        return {
            valid: false,
            error: 'userName exceeds maximum length of 256 characters',
        };
    }

    // Validate emails if provided
    if (request.emails && Array.isArray(request.emails)) {
        for (const email of request.emails) {
            if (!email.value || !isValidEmail(email.value)) {
                return {
                    valid: false,
                    error: `Invalid email format: ${email.value}`,
                };
            }
        }
    }

    // Validate name if provided
    if (request.name) {
        if (request.name.givenName && request.name.givenName.length > 128) {
            return {
                valid: false,
                error: 'name.givenName exceeds maximum length of 128 characters',
            };
        }
        if (request.name.familyName && request.name.familyName.length > 128) {
            return {
                valid: false,
                error: 'name.familyName exceeds maximum length of 128 characters',
            };
        }
    }

    // Validate displayName if provided
    if (request.displayName && request.displayName.length > 256) {
        return {
            valid: false,
            error: 'displayName exceeds maximum length of 256 characters',
        };
    }

    // Validate password if provided (minimum security requirements)
    if (request.password !== undefined) {
        if (typeof request.password !== 'string') {
            return {
                valid: false,
                error: 'password must be a string',
            };
        }
        if (request.password.length < 8) {
            return {
                valid: false,
                error: 'password must be at least 8 characters',
            };
        }
        if (request.password.length > 128) {
            return {
                valid: false,
                error: 'password exceeds maximum length of 128 characters',
            };
        }
    }

    // Validate Enterprise User Extension if provided
    const enterpriseExt = request['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'];
    if (enterpriseExt) {
        const enterpriseValidation = validateEnterpriseExtension(enterpriseExt);
        if (!enterpriseValidation.valid) {
            return enterpriseValidation;
        }
    }

    return { valid: true };
}

// =============================================================================
// Enterprise Extension Validation
// =============================================================================

/**
 * Validate Enterprise User Extension attributes per RFC 7643 Section 4.3.
 */
function validateEnterpriseExtension(
    enterprise: NonNullable<ScimUserCreateRequest['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']>
): ValidationResult {
    // Validate string field lengths
    const stringFields: Array<{ name: string; value?: string; maxLength: number }> = [
        { name: 'employeeNumber', value: enterprise.employeeNumber, maxLength: 64 },
        { name: 'costCenter', value: enterprise.costCenter, maxLength: 64 },
        { name: 'organization', value: enterprise.organization, maxLength: 128 },
        { name: 'division', value: enterprise.division, maxLength: 128 },
        { name: 'department', value: enterprise.department, maxLength: 128 },
    ];

    for (const field of stringFields) {
        if (field.value !== undefined) {
            if (typeof field.value !== 'string') {
                return { valid: false, error: `Enterprise extension ${field.name} must be a string` };
            }
            if (field.value.length > field.maxLength) {
                return {
                    valid: false,
                    error: `Enterprise extension ${field.name} exceeds maximum length of ${field.maxLength} characters`,
                };
            }
        }
    }

    // Validate manager reference
    if (enterprise.manager) {
        if (enterprise.manager.value !== undefined && typeof enterprise.manager.value !== 'string') {
            return { valid: false, error: 'Enterprise extension manager.value must be a string' };
        }
        if (enterprise.manager.displayName !== undefined) {
            if (typeof enterprise.manager.displayName !== 'string') {
                return { valid: false, error: 'Enterprise extension manager.displayName must be a string' };
            }
            if (enterprise.manager.displayName.length > 256) {
                return {
                    valid: false,
                    error: 'Enterprise extension manager.displayName exceeds maximum length of 256 characters',
                };
            }
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
    if (!request.schemas || !Array.isArray(request.schemas)) {
        return {
            valid: false,
            error: 'schemas is required',
        };
    }

    if (!request.schemas.includes(SCIM_PATCH_SCHEMA)) {
        return {
            valid: false,
            error: `Invalid schema. Expected: ${SCIM_PATCH_SCHEMA}`,
        };
    }

    // Validate Operations
    if (!request.Operations || !Array.isArray(request.Operations)) {
        return {
            valid: false,
            error: 'Operations is required and must be an array',
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
        const op = request.Operations[i];
        const opValidation = validatePatchOperation(op, i);
        if (!opValidation.valid) {
            return opValidation;
        }
    }

    return { valid: true };
}

/**
 * Validate a single PATCH operation.
 */
function validatePatchOperation(op: ScimPatchOperation, index: number): ValidationResult {
    // op is REQUIRED
    if (!op.op) {
        return {
            valid: false,
            error: `Operations[${index}].op is required`,
        };
    }

    const validOps = ['add', 'remove', 'replace'];
    if (!validOps.includes(op.op.toLowerCase())) {
        return {
            valid: false,
            error: `Operations[${index}].op must be one of: ${validOps.join(', ')}`,
        };
    }

    // For add and replace, value is REQUIRED
    if ((op.op === 'add' || op.op === 'replace') && op.value === undefined) {
        return {
            valid: false,
            error: `Operations[${index}].value is required for ${op.op} operation`,
        };
    }

    // Validate path if provided
    if (op.path !== undefined && typeof op.path !== 'string') {
        return {
            valid: false,
            error: `Operations[${index}].path must be a string`,
        };
    }

    return { valid: true };
}

// =============================================================================
// Extract Primary Email
// =============================================================================

/**
 * Extract the primary email from SCIM emails array.
 * Falls back to first email if no primary is marked.
 *
 * @param emails - Array of SCIM email objects
 * @returns Primary email value or undefined
 */
export function extractPrimaryEmail(emails: readonly ScimEmail[] | undefined): string | undefined {
    if (!emails || emails.length === 0) {
        return undefined;
    }

    // Find primary email
    const primary = emails.find(e => e.primary === true);
    if (primary) {
        return primary.value;
    }

    // Fall back to first email
    return emails[0].value;
}
