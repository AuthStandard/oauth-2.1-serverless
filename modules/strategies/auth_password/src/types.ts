/**
 * OAuth Server - Password Authentication Strategy Types
 *
 * Type definitions for the password authentication flow.
 * These types are local to the password strategy module and mirror
 * the shared_types definitions for the specific fields needed.
 *
 * Note: Audit types are provided by @oauth-server/shared.
 */

import type { APIGatewayProxyResultV2 } from 'aws-lambda';

// =============================================================================
// DynamoDB Entity Types
// =============================================================================

/**
 * Login session item stored in DynamoDB during the authentication flow.
 * Created by the authorize endpoint, consumed by the callback endpoint.
 */
export interface LoginSessionItem {
    /** Partition key: SESSION#<session_id> */
    PK: `SESSION#${string}`;
    /** Sort key: Always 'METADATA' for session items */
    SK: 'METADATA';
    /** GSI1 partition key for client-based queries */
    GSI1PK: `CLIENT#${string}`;
    /** GSI1 sort key for session ordering */
    GSI1SK: `SESSION#${string}`;
    /** Entity type discriminator */
    entityType: 'LOGIN_SESSION';
    /** Unique session identifier (UUID) */
    sessionId: string;
    /** OAuth client ID that initiated the flow */
    clientId: string;
    /** Requested OAuth scopes (space-delimited) */
    scope: string;
    /** PKCE code challenge (base64url-encoded SHA256) */
    codeChallenge: string;
    /** PKCE challenge method (OAuth 2.1 mandates S256) */
    codeChallengeMethod: 'S256';
    /** Validated redirect URI */
    redirectUri: string;
    /** OAuth state parameter for CSRF protection */
    state?: string;
    /** OIDC nonce for replay protection */
    nonce?: string;
    /** Response type (always 'code' for OAuth 2.1) */
    responseType: 'code';
    /** Authentication strategy identifier */
    authStrategyId?: string;
    /** User's subject ID after successful authentication (full auth complete) */
    authenticatedUserId?: string;
    /** User's subject ID pending MFA verification */
    pendingMfaUserId?: string;
    /** ISO 8601 timestamp of authentication */
    authenticatedAt?: string;
    /** Authentication method used (e.g., 'password', 'saml') */
    authMethod?: string;
    /** TTL for automatic DynamoDB expiration (Unix epoch seconds) */
    ttl: number;
    /** ISO 8601 creation timestamp */
    createdAt: string;
    /** ISO 8601 last update timestamp */
    updatedAt: string;
}

/**
 * User item stored in DynamoDB.
 * Contains profile and authentication data for password-based login.
 */
export interface UserItem {
    /** Partition key: USER#<sub> */
    PK: `USER#${string}`;
    /** Sort key: Always 'PROFILE' for user items */
    SK: 'PROFILE';
    /** GSI1 partition key for email-based lookups */
    GSI1PK: `EMAIL#${string}`;
    /** GSI1 sort key: Always 'USER' for user items */
    GSI1SK: 'USER';
    /** Entity type discriminator */
    entityType: 'USER';
    /** User's unique subject identifier (UUID) */
    sub: string;
    /** User's email address (normalized to lowercase) */
    email: string;
    /** Whether the email has been verified */
    emailVerified: boolean;
    /** IANA timezone identifier */
    zoneinfo: string;
    /** Argon2id password hash (optional for non-password users) */
    passwordHash?: string;
    /** User profile information */
    profile: UserProfile;
    /** Account status */
    status: UserStatus;
    /** Failed login attempt counter for brute force protection */
    failedLoginAttempts?: number;
    /** ISO 8601 timestamp of last failed login */
    lastFailedLoginAt?: string;
    /** ISO 8601 timestamp until which the account is locked */
    lockedUntil?: string;
    /** Whether MFA is enabled for this user */
    mfaEnabled?: boolean;
    /** MFA method (currently only 'totp' supported) */
    mfaMethod?: 'totp';
    /** ISO 8601 creation timestamp */
    createdAt: string;
    /** ISO 8601 last update timestamp */
    updatedAt: string;
    /** TTL for automatic DynamoDB expiration (Unix epoch seconds) */
    ttl?: number;
}

/**
 * User profile information following OIDC standard claims.
 */
export interface UserProfile {
    /** Given/first name */
    givenName?: string;
    /** Family/last name */
    familyName?: string;
    /** Profile picture URL */
    picture?: string;
    /** BCP 47 locale code (e.g., 'en-US') */
    locale?: string;
}

/**
 * User account status.
 */
export type UserStatus = 'ACTIVE' | 'SUSPENDED' | 'PENDING_VERIFICATION';

// =============================================================================
// Environment Configuration
// =============================================================================

/**
 * Environment configuration for the login handler.
 */
export interface LoginEnvConfig {
    tableName: string;
    csrfSecret: string;
    verifyUrl: string;
    brandName: string;
}

/**
 * Environment configuration for the verify handler.
 */
export interface VerifyEnvConfig {
    tableName: string;
    csrfSecret: string;
    loginUrl: string;
    callbackUrl: string;
    maxFailedAttempts: number;
    lockoutDurationSeconds: number;
    /** URL to redirect to for MFA validation (optional - if not set, MFA is skipped) */
    mfaValidateUrl?: string;
}

/**
 * Environment configuration for the forgot password handler.
 */
export interface ForgotEnvConfig {
    tableName: string;
    resetTokenTtl: number;
    resetPageUrl: string;
    sesSenderEmail: string;
    sesSenderName: string;
    sesConfigurationSet?: string;
    passwordResetTemplate: string;
}

/**
 * Password policy configuration.
 */
export interface PasswordPolicy {
    minLength: number;
    requireUppercase: boolean;
    requireLowercase: boolean;
    requireNumber: boolean;
    requireSpecial: boolean;
}

/**
 * Environment configuration for the password reset handler.
 */
export interface ResetEnvConfig {
    tableName: string;
    passwordPolicy: PasswordPolicy;
}

/**
 * Password reset token stored in DynamoDB.
 * PK: RESET#<token_hash>  SK: METADATA
 */
export interface PasswordResetTokenItem {
    PK: `RESET#${string}`;
    SK: 'METADATA';
    entityType: 'PASSWORD_RESET_TOKEN';
    tokenHash: string;
    userId: string;
    email: string;
    createdAt: string;
    ttl: number;
}

// =============================================================================
// Request/Response Types
// =============================================================================

/**
 * Parsed form data from the login form submission.
 */
export interface LoginFormData {
    email: string;
    password: string;
    session_id: string;
    csrf_token: string;
}

/**
 * Parameters for rendering the login form.
 */
export interface LoginFormParams {
    sessionId: string;
    csrfToken: string;
    verifyUrl: string;
    error?: string;
    /** Brand name displayed in the login form. Defaults to 'OAuth Server'. */
    brandName?: string;
}

// =============================================================================
// Response Type
// =============================================================================

export type LambdaResponse = APIGatewayProxyResultV2;
