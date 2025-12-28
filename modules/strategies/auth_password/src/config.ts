/**
 * OAuth Server - Password Authentication Strategy Configuration
 *
 * Centralized environment configuration with validation.
 * All configuration values are injected via Terraform environment variables.
 */

import type { LoginEnvConfig, VerifyEnvConfig, ForgotEnvConfig, ResetEnvConfig } from './types';

// =============================================================================
// Configuration Defaults
// =============================================================================

/**
 * Default values for optional configuration.
 * These are fallbacks only - production deployments should set all values explicitly.
 */
const DEFAULTS = {
    VERIFY_URL: '/auth/password/verify',
    LOGIN_URL: '/auth/password/login',
    CALLBACK_URL: '/authorize/callback',
    MAX_FAILED_ATTEMPTS: 5,
    LOCKOUT_DURATION_SECONDS: 900, // 15 minutes
    BRAND_NAME: 'OAuth Server',
    RESET_TOKEN_TTL: 3600, // 1 hour
    RESET_PAGE_URL: '/auth/password/reset-form',
    PASSWORD_MIN_LENGTH: 8,
    PASSWORD_REQUIRE_UPPERCASE: true,
    PASSWORD_REQUIRE_LOWERCASE: true,
    PASSWORD_REQUIRE_NUMBER: true,
    PASSWORD_REQUIRE_SPECIAL: false,
} as const;

// =============================================================================
// Environment Validation
// =============================================================================

/**
 * Validates that a required environment variable is present.
 * @throws Error if the variable is missing
 */
function requireEnv(name: string): string {
    const value = process.env[name];
    if (!value) {
        throw new Error(`Missing required environment variable: ${name}`);
    }
    return value;
}

/**
 * Gets an optional environment variable with a default value.
 */
function optionalEnv(name: string, defaultValue: string): string {
    return process.env[name] || defaultValue;
}

/**
 * Gets an optional numeric environment variable with a default value.
 */
function optionalNumericEnv(name: string, defaultValue: number): number {
    const value = process.env[name];
    if (!value) {
        return defaultValue;
    }
    const parsed = parseInt(value, 10);
    if (isNaN(parsed)) {
        throw new Error(`Invalid numeric value for ${name}: ${value}`);
    }
    return parsed;
}

// =============================================================================
// Configuration Loaders
// =============================================================================

let loginConfigCache: LoginEnvConfig | null = null;
let verifyConfigCache: VerifyEnvConfig | null = null;
let forgotConfigCache: ForgotEnvConfig | null = null;
let resetConfigCache: ResetEnvConfig | null = null;

/**
 * Load and validate configuration for the login handler.
 * Configuration is cached after first load for Lambda warm starts.
 */
export function getLoginConfig(): LoginEnvConfig {
    if (loginConfigCache) {
        return loginConfigCache;
    }

    loginConfigCache = {
        tableName: requireEnv('TABLE_NAME'),
        csrfSecret: requireEnv('CSRF_SECRET'),
        verifyUrl: optionalEnv('VERIFY_URL', DEFAULTS.VERIFY_URL),
        brandName: optionalEnv('BRAND_NAME', DEFAULTS.BRAND_NAME),
    };

    return loginConfigCache;
}

/**
 * Load and validate configuration for the verify handler.
 * Configuration is cached after first load for Lambda warm starts.
 */
export function getVerifyConfig(): VerifyEnvConfig {
    if (verifyConfigCache) {
        return verifyConfigCache;
    }

    verifyConfigCache = {
        tableName: requireEnv('TABLE_NAME'),
        csrfSecret: requireEnv('CSRF_SECRET'),
        loginUrl: optionalEnv('LOGIN_URL', DEFAULTS.LOGIN_URL),
        callbackUrl: optionalEnv('CALLBACK_URL', DEFAULTS.CALLBACK_URL),
        maxFailedAttempts: optionalNumericEnv('MAX_FAILED_ATTEMPTS', DEFAULTS.MAX_FAILED_ATTEMPTS),
        lockoutDurationSeconds: optionalNumericEnv('LOCKOUT_DURATION_SECONDS', DEFAULTS.LOCKOUT_DURATION_SECONDS),
        mfaValidateUrl: process.env.MFA_VALIDATE_URL || undefined,
    };

    return verifyConfigCache;
}

/**
 * Clear configuration cache (useful for testing).
 */
export function clearConfigCache(): void {
    loginConfigCache = null;
    verifyConfigCache = null;
    forgotConfigCache = null;
    resetConfigCache = null;
}

/**
 * Load and validate configuration for the forgot password handler.
 * Configuration is cached after first load for Lambda warm starts.
 */
export function getForgotConfig(): ForgotEnvConfig {
    if (forgotConfigCache) {
        return forgotConfigCache;
    }

    forgotConfigCache = {
        tableName: requireEnv('TABLE_NAME'),
        resetTokenTtl: optionalNumericEnv('RESET_TOKEN_TTL', DEFAULTS.RESET_TOKEN_TTL),
        resetPageUrl: requireEnv('RESET_PAGE_URL'),
        sesSenderEmail: requireEnv('SES_SENDER_EMAIL'),
        sesSenderName: optionalEnv('SES_SENDER_NAME', DEFAULTS.BRAND_NAME),
        sesConfigurationSet: process.env.SES_CONFIGURATION_SET,
        passwordResetTemplate: requireEnv('PASSWORD_RESET_TEMPLATE'),
    };

    return forgotConfigCache;
}

/**
 * Load and validate configuration for the password reset handler.
 * Configuration is cached after first load for Lambda warm starts.
 */
export function getResetConfig(): ResetEnvConfig {
    if (resetConfigCache) {
        return resetConfigCache;
    }

    resetConfigCache = {
        tableName: requireEnv('TABLE_NAME'),
        passwordPolicy: {
            minLength: optionalNumericEnv('PASSWORD_MIN_LENGTH', DEFAULTS.PASSWORD_MIN_LENGTH),
            requireUppercase: process.env.PASSWORD_REQUIRE_UPPERCASE !== 'false',
            requireLowercase: process.env.PASSWORD_REQUIRE_LOWERCASE !== 'false',
            requireNumber: process.env.PASSWORD_REQUIRE_NUMBER !== 'false',
            requireSpecial: process.env.PASSWORD_REQUIRE_SPECIAL === 'true',
        },
    };

    return resetConfigCache;
}
