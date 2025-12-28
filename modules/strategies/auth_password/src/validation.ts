/**
 * OAuth Server - Input Validation
 *
 * Validation utilities for the password authentication flow.
 * Note: Email validation and normalization are in @oauth-server/shared.
 */

// =============================================================================
// Session Validation
// =============================================================================

/**
 * Check if a session has expired based on its TTL.
 */
export function isSessionExpired(ttl: number | undefined): boolean {
    if (!ttl) {
        return true;
    }
    const nowEpochSeconds = Math.floor(Date.now() / 1000);
    return ttl < nowEpochSeconds;
}

// =============================================================================
// Account Lockout Validation
// =============================================================================

/**
 * Check if an account is currently locked.
 */
export function isAccountLocked(lockedUntil: string | undefined): boolean {
    if (!lockedUntil) {
        return false;
    }
    const lockTime = new Date(lockedUntil).getTime();
    return Date.now() < lockTime;
}

/**
 * Calculate the lockout expiration time.
 */
export function calculateLockoutExpiry(durationSeconds: number): string {
    const expiryTime = new Date(Date.now() + durationSeconds * 1000);
    return expiryTime.toISOString();
}


// =============================================================================
// Password Strength Validation
// =============================================================================

import type { PasswordPolicy } from './types';

/**
 * Result of password strength validation.
 */
export interface PasswordStrengthResult {
    valid: boolean;
    errors: string[];
}

/**
 * Validate password against strength requirements.
 *
 * @param password - The password to validate
 * @param policy - Password policy configuration
 * @returns Validation result with any errors
 */
export function validatePasswordStrength(
    password: string,
    policy: PasswordPolicy
): PasswordStrengthResult {
    const errors: string[] = [];

    // Check minimum length
    if (password.length < policy.minLength) {
        errors.push(`Password must be at least ${policy.minLength} characters long`);
    }

    // Check for uppercase letter
    if (policy.requireUppercase && !/[A-Z]/.test(password)) {
        errors.push('Password must contain at least one uppercase letter');
    }

    // Check for lowercase letter
    if (policy.requireLowercase && !/[a-z]/.test(password)) {
        errors.push('Password must contain at least one lowercase letter');
    }

    // Check for number
    if (policy.requireNumber && !/[0-9]/.test(password)) {
        errors.push('Password must contain at least one number');
    }

    // Check for special character
    if (policy.requireSpecial && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
        errors.push('Password must contain at least one special character');
    }

    return {
        valid: errors.length === 0,
        errors,
    };
}
