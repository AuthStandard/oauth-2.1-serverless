/**
 * OAuth Server - Email Validation
 *
 * Email address validation and normalization utilities.
 *
 * Security Considerations:
 * - Strict validation prevents injection attacks via malformed emails
 * - Normalization ensures consistent storage and lookup
 * - Length limits prevent DoS via oversized inputs
 *
 * @see RFC 5321 Section 4.5.3.1.3 - Maximum email length (254 characters)
 * @see RFC 5321 Section 4.5.3.1.1 - Maximum local part length (64 characters)
 */

// =============================================================================
// Constants
// =============================================================================

/** Maximum allowed email length per RFC 5321 Section 4.5.3.1.3 */
const MAX_EMAIL_LENGTH = 254;

/** Maximum local part length per RFC 5321 Section 4.5.3.1.1 */
const MAX_LOCAL_PART_LENGTH = 64;

/**
 * Email validation regex pattern.
 *
 * Validates production-ready email formats per RFC 5321:
 * - Local part: alphanumeric, allows dots, hyphens, underscores, plus signs
 * - Domain: alphanumeric segments separated by dots, no leading/trailing hyphens
 * - TLD: minimum 2 alphabetic characters
 *
 * This is intentionally stricter than RFC 5322 to reject edge cases
 * that are technically valid but rarely used in practice. This approach
 * prevents potential injection attacks and ensures compatibility with
 * common email providers.
 *
 * Supports:
 * - Single character local parts (e.g., a@example.com)
 * - Plus addressing (e.g., user+tag@example.com)
 * - Subdomains (e.g., user@mail.example.com)
 *
 * @see RFC 5321 Section 4.1.2 - Command Argument Syntax
 */
const EMAIL_REGEX = /^[a-zA-Z0-9][a-zA-Z0-9._+-]*@[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;

// =============================================================================
// Email Validation
// =============================================================================

/**
 * Validate an email address.
 *
 * Performs comprehensive validation including:
 * - Type checking and null safety
 * - Early length check before regex (DoS protection)
 * - RFC 5321 length constraints
 * - Structural validation (local part, domain, TLD)
 * - Character whitelist enforcement
 *
 * @param email - The email address to validate
 * @returns True if valid (also narrows type to string)
 *
 * @example
 * ```typescript
 * if (isValidEmail(input)) {
 *   // TypeScript knows input is string here
 *   const normalized = normalizeEmail(input);
 * }
 * ```
 */
export function isValidEmail(email: string | undefined | null): email is string {
    if (email === null || email === undefined || typeof email !== 'string') {
        return false;
    }

    // Early length check before any processing (DoS protection)
    // Check raw length first to avoid expensive operations on huge inputs
    if (email.length > MAX_EMAIL_LENGTH) {
        return false;
    }

    const trimmed = email.trim();

    // RFC 5321 maximum length check
    if (trimmed.length === 0 || trimmed.length > MAX_EMAIL_LENGTH) {
        return false;
    }

    // Structural validation: must have exactly one @ with content on both sides
    const atIndex = trimmed.lastIndexOf('@');
    if (atIndex === -1 || atIndex === 0) {
        return false;
    }

    const localPart = trimmed.substring(0, atIndex);
    const domain = trimmed.substring(atIndex + 1);

    // Local part length validation per RFC 5321
    if (localPart.length === 0 || localPart.length > MAX_LOCAL_PART_LENGTH) {
        return false;
    }

    // Reject consecutive dots and leading/trailing dots in local part
    if (localPart.includes('..') || localPart.startsWith('.') || localPart.endsWith('.')) {
        return false;
    }

    // Domain must exist and contain at least one dot (for TLD)
    if (domain.length === 0 || !domain.includes('.')) {
        return false;
    }

    // Single-character local parts are valid (e.g., a@example.com)
    // The main regex handles this case correctly
    return EMAIL_REGEX.test(trimmed);
}

/**
 * Normalize an email address for consistent storage and lookup.
 *
 * Normalization ensures case-insensitive email matching by converting
 * to lowercase. While the local part (before @) is technically case-sensitive
 * per RFC 5321, virtually all email providers treat it as case-insensitive.
 *
 * This normalization is critical for:
 * - Preventing duplicate user registrations with different casing
 * - Ensuring consistent GSI1 lookups in DynamoDB
 * - Matching user input during login to stored email
 *
 * @param email - The email address to normalize
 * @returns Lowercase, trimmed email
 *
 * @example
 * ```typescript
 * normalizeEmail('User@Example.COM') // Returns: 'user@example.com'
 * ```
 */
export function normalizeEmail(email: string): string {
    return email.toLowerCase().trim();
}
