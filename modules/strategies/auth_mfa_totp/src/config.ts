/**
 * OAuth Server - TOTP MFA Strategy Configuration
 *
 * Centralized environment configuration with validation.
 * All configuration values are injected via Terraform environment variables.
 */

import type { SetupEnvConfig, VerifyEnvConfig, ValidateEnvConfig, DisableEnvConfig } from './types';

// =============================================================================
// Configuration Defaults
// =============================================================================

const DEFAULTS = {
    TOTP_DIGITS: 6,
    TOTP_PERIOD: 30,
    TOTP_WINDOW: 1,
    BACKUP_CODES_COUNT: 10,
} as const;

// =============================================================================
// Environment Validation
// =============================================================================

function requireEnv(name: string): string {
    const value = process.env[name];
    if (!value) {
        throw new Error(`Missing required environment variable: ${name}`);
    }
    return value;
}

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

let setupConfigCache: SetupEnvConfig | null = null;
let verifyConfigCache: VerifyEnvConfig | null = null;
let validateConfigCache: ValidateEnvConfig | null = null;
let disableConfigCache: DisableEnvConfig | null = null;

export function getSetupConfig(): SetupEnvConfig {
    if (setupConfigCache) {
        return setupConfigCache;
    }

    setupConfigCache = {
        tableName: requireEnv('TABLE_NAME'),
        totpIssuer: requireEnv('TOTP_ISSUER'),
        totpDigits: optionalNumericEnv('TOTP_DIGITS', DEFAULTS.TOTP_DIGITS),
        totpPeriod: optionalNumericEnv('TOTP_PERIOD', DEFAULTS.TOTP_PERIOD),
        backupCodesCount: optionalNumericEnv('BACKUP_CODES_COUNT', DEFAULTS.BACKUP_CODES_COUNT),
    };

    return setupConfigCache;
}

export function getVerifyConfig(): VerifyEnvConfig {
    if (verifyConfigCache) {
        return verifyConfigCache;
    }

    verifyConfigCache = {
        tableName: requireEnv('TABLE_NAME'),
        totpDigits: optionalNumericEnv('TOTP_DIGITS', DEFAULTS.TOTP_DIGITS),
        totpPeriod: optionalNumericEnv('TOTP_PERIOD', DEFAULTS.TOTP_PERIOD),
        totpWindow: optionalNumericEnv('TOTP_WINDOW', DEFAULTS.TOTP_WINDOW),
    };

    return verifyConfigCache;
}

export function getValidateConfig(): ValidateEnvConfig {
    if (validateConfigCache) {
        return validateConfigCache;
    }

    validateConfigCache = {
        tableName: requireEnv('TABLE_NAME'),
        totpDigits: optionalNumericEnv('TOTP_DIGITS', DEFAULTS.TOTP_DIGITS),
        totpPeriod: optionalNumericEnv('TOTP_PERIOD', DEFAULTS.TOTP_PERIOD),
        totpWindow: optionalNumericEnv('TOTP_WINDOW', DEFAULTS.TOTP_WINDOW),
    };

    return validateConfigCache;
}

export function getDisableConfig(): DisableEnvConfig {
    if (disableConfigCache) {
        return disableConfigCache;
    }

    disableConfigCache = {
        tableName: requireEnv('TABLE_NAME'),
        totpDigits: optionalNumericEnv('TOTP_DIGITS', DEFAULTS.TOTP_DIGITS),
        totpPeriod: optionalNumericEnv('TOTP_PERIOD', DEFAULTS.TOTP_PERIOD),
        totpWindow: optionalNumericEnv('TOTP_WINDOW', DEFAULTS.TOTP_WINDOW),
    };

    return disableConfigCache;
}

export function clearConfigCache(): void {
    setupConfigCache = null;
    verifyConfigCache = null;
    validateConfigCache = null;
    disableConfigCache = null;
}
