/**
 * OAuth Server - TOTP MFA Strategy Types
 *
 * Type definitions for the TOTP multi-factor authentication flow.
 */

import type { APIGatewayProxyResultV2 } from 'aws-lambda';

// =============================================================================
// Environment Configuration
// =============================================================================

export interface SetupEnvConfig {
    tableName: string;
    totpIssuer: string;
    totpDigits: number;
    totpPeriod: number;
    backupCodesCount: number;
}

export interface VerifyEnvConfig {
    tableName: string;
    totpDigits: number;
    totpPeriod: number;
    totpWindow: number;
}

export interface ValidateEnvConfig {
    tableName: string;
    totpDigits: number;
    totpPeriod: number;
    totpWindow: number;
}

export interface DisableEnvConfig {
    tableName: string;
    totpDigits: number;
    totpPeriod: number;
    totpWindow: number;
}

// =============================================================================
// DynamoDB Entity Types
// =============================================================================

/**
 * MFA setup token stored temporarily during enrollment.
 * PK: MFA_SETUP#<user_id>  SK: METADATA
 */
export interface MfaSetupTokenItem {
    PK: `MFA_SETUP#${string}`;
    SK: 'METADATA';
    entityType: 'MFA_SETUP_TOKEN';
    userId: string;
    secret: string;
    backupCodes: string[];
    createdAt: string;
    ttl: number;
}

/**
 * User MFA configuration stored in user profile.
 */
export interface UserMfaConfig {
    mfaEnabled: boolean;
    mfaMethod?: 'totp';
    totpSecret?: string;
    backupCodesHashes?: string[];
    mfaEnabledAt?: string;
}

// =============================================================================
// Request/Response Types
// =============================================================================

export interface SetupRequest {
    userId: string;
    email: string;
}

export interface SetupResponse {
    secret: string;
    qrCodeDataUrl: string;
    backupCodes: string[];
}

export interface VerifyRequest {
    userId: string;
    code: string;
}

export interface ValidateRequest {
    sessionId: string;
    code: string;
}

export interface DisableRequest {
    userId: string;
    code: string;
}

// =============================================================================
// Response Type
// =============================================================================

export type LambdaResponse = APIGatewayProxyResultV2;
