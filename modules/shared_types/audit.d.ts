/**
 * OAuth Server - Lean Audit Schema
 *
 * SOC2-compliant structured logging interfaces.
 * All audit events are JSON-formatted for CloudWatch.
 *
 * This file defines the contract for the AuditLogger utility class.
 *
 * SOC2 Compliance Requirements:
 * - CC6.1: Logical access security events must be logged
 * - CC7.2: System operations must be monitored
 * - All events include timestamp, actor, action, and IP address
 *
 * @see SOC2 Trust Services Criteria
 */

// =============================================================================
// Audit Actions
// =============================================================================

/**
 * Enumeration of all auditable actions in the system.
 * Each action represents a security-relevant event per SOC2 requirements.
 *
 * @see SOC2 CC6.1 - Logical and Physical Access Controls
 * @see SOC2 CC7.2 - System Operations Monitoring
 */
export type AuditAction =
    | 'LOGIN_SUCCESS'
    | 'LOGIN_FAILURE'
    | 'LOGOUT'
    | 'TOKEN_ISSUED'
    | 'TOKEN_REVOKED'
    | 'TOKEN_REFRESHED'
    | 'TOKEN_INTROSPECTED'
    | 'AUTH_CODE_ISSUED'
    | 'AUTH_CODE_EXCHANGED'
    | 'AUTH_SESSION_CREATED'
    | 'SAML_ASSERTION_RECEIVED'
    | 'CLIENT_AUTHENTICATED'
    | 'CLIENT_AUTH_FAILED'
    // RFC 7591/7592 Client Registry Actions
    | 'CLIENT_CREATED'
    | 'CLIENT_READ'
    | 'CLIENT_UPDATED'
    | 'CLIENT_DELETED'
    | 'CLIENT_READ_FAILED'
    | 'CLIENT_UPDATE_FAILED'
    | 'CLIENT_DELETE_FAILED'
    // SCIM 2.0 User Provisioning Actions
    | 'USER_PROVISIONED'
    | 'USER_UPDATED'
    | 'USER_DEACTIVATED'
    | 'USER_DELETED'
    // SCIM 2.0 Group Provisioning Actions
    | 'GROUP_CREATED'
    | 'GROUP_UPDATED'
    | 'GROUP_DELETED'
    // Password Reset Actions
    | 'PASSWORD_RESET_REQUESTED'
    | 'PASSWORD_RESET_SUCCESS'
    | 'PASSWORD_RESET_FAILED'
    // MFA Actions
    | 'MFA_SETUP_INITIATED'
    | 'MFA_SETUP_FAILED'
    | 'MFA_ENABLED'
    | 'MFA_DISABLED'
    | 'MFA_DISABLE_FAILED'
    | 'MFA_VALIDATION_SUCCESS'
    | 'MFA_VALIDATION_FAILED';

// =============================================================================
// Actor Types
// =============================================================================

/**
 * Represents the entity performing the audited action.
 * Can be a user (sub), client, or system process.
 */
export type AuditActor =
    | { type: 'USER'; sub: string }
    | { type: 'CLIENT'; clientId: string }
    | { type: 'SYSTEM'; process?: string }
    | { type: 'ANONYMOUS' };

// =============================================================================
// Audit Log Entry
// =============================================================================

/**
 * Structured audit log entry for CloudWatch.
 * Every security-relevant event must produce an entry matching this interface.
 * 
 * @example
 * ```typescript
 * const entry: AuditLogEntry = {
 *   level: 'AUDIT',
 *   timestamp: '2024-01-15T10:30:00.000Z',
 *   requestId: 'abc123-def456-ghi789',
 *   action: 'LOGIN_SUCCESS',
 *   ip: '192.168.1.1',
 *   actor: { type: 'USER', sub: 'user-uuid-here' },
 *   details: { method: 'password', mfaUsed: false }
 * };
 * ```
 */
export interface AuditLogEntry {
    /** 
     * Log level - always 'AUDIT' for audit entries.
     * This allows filtering audit logs from other log levels.
     */
    level: 'AUDIT';

    /** 
     * ISO 8601 timestamp of when the action occurred.
     * Must be in UTC (Z suffix).
     * @example "2024-01-15T10:30:00.000Z"
     */
    timestamp: string;

    /**
     * AWS Request ID for tracing.
     * Obtained from Lambda context or API Gateway.
     * Optional when using AuditLogger - filled from context.
     */
    requestId?: string;

    /**
     * The auditable action that occurred.
     */
    action: AuditAction;

    /**
     * Source IP address of the request.
     * Obtained from API Gateway request context.
     * Optional when using AuditLogger - filled from context.
     */
    ip?: string;

    /**
     * The entity that performed the action.
     * User Sub, Client ID, or system identifier.
     */
    actor: AuditActor;

    /**
     * Additional metadata specific to the action.
     * Structure varies by action type.
     */
    details: Record<string, unknown>;
}

// =============================================================================
// Action-Specific Detail Types (Optional Strict Typing)
// =============================================================================

/** Details for LOGIN_SUCCESS and LOGIN_FAILURE actions */
export interface LoginDetails {
    /** Authentication method used */
    method: 'password' | 'saml';
    /** Email attempted (may be partial/masked for failures) */
    email?: string;
    /** Failure reason (for LOGIN_FAILURE only) */
    reason?: string;
    /** Whether MFA was used */
    mfaUsed?: boolean;
    /** Whether MFA is pending (password verified, awaiting TOTP) */
    mfaPending?: boolean;
}

/** Details for TOKEN_ISSUED action */
export interface TokenIssuedDetails {
    /** Type of token issued */
    tokenType: 'access_token' | 'refresh_token' | 'id_token';
    /** Client that received the token */
    clientId: string;
    /** Scopes granted */
    scopes: string[];
    /** Token expiration time (ISO 8601) */
    expiresAt: string;
    /** Grant type used */
    grantType: string;
}

/** Details for TOKEN_REVOKED action */
export interface TokenRevokedDetails {
    /** Type of token revoked */
    tokenType: 'access_token' | 'refresh_token';
    /** Reason for revocation */
    reason: 'user_logout' | 'admin_action' | 'rotation' | 'expiration';
    /** Token hint (partial hash for identification) */
    tokenHint?: string;
}

/** Details for AUTH_SESSION_CREATED action */
export interface AuthSessionCreatedDetails {
    /** Session identifier */
    sessionId: string;
    /** Requested scopes */
    scope: string;
    /** Redirect URI for the session */
    redirectUri: string;
}

/** Details for AUTH_CODE_ISSUED action */
export interface AuthCodeIssuedDetails {
    /** Client that received the code */
    clientId: string;
    /** Scopes granted */
    scopes: string[];
    /** Code expiration time (ISO 8601) */
    expiresAt: string;
}

/** Details for AUTH_CODE_EXCHANGED action */
export interface AuthCodeExchangedDetails {
    /** Client that exchanged the code */
    clientId: string;
    /** Grant type used */
    grantType: 'authorization_code';
}

/** Details for TOKEN_REFRESHED action */
export interface TokenRefreshedDetails {
    /** Client that refreshed the token */
    clientId: string;
    /** Scopes in the new token */
    scopes: string[];
    /** Whether the refresh token was rotated */
    tokenRotated: boolean;
}

/** Details for SAML_ASSERTION_RECEIVED action */
export interface SAMLAssertionDetails {
    /** SAML IdP issuer */
    issuer: string;
    /** Assertion ID */
    assertionId: string;
    /** Whether the assertion was valid */
    valid: boolean;
    /** Validation error (if invalid) */
    validationError?: string;
    /** NameID from the assertion */
    nameId?: string;
}

/** Details for TOKEN_INTROSPECTED action */
export interface TokenIntrospectedDetails {
    /** Whether the token was active */
    active: boolean;
    /** Token type introspected */
    tokenType: 'access_token' | 'refresh_token';
    /** Client that owns the token (if active) */
    tokenClientId?: string;
    /** Requesting client ID */
    requestingClientId: string;
}

/** Details for CLIENT_AUTHENTICATED action */
export interface ClientAuthenticatedDetails {
    /** Client ID that authenticated */
    clientId: string;
    /** Authentication method used */
    method: 'client_secret_basic' | 'client_secret_post' | 'private_key_jwt' | 'none';
}

/** Details for CLIENT_AUTH_FAILED action */
export interface ClientAuthFailedDetails {
    /** Client ID that failed authentication (if provided) */
    clientId?: string;
    /** Reason for failure */
    reason: 'invalid_client' | 'invalid_secret' | 'expired_credentials' | 'unknown_client';
}

/** Details for LOGOUT action */
export interface LogoutDetails {
    /** Client ID that initiated the logout */
    clientId: string;
    /** Session ID that was terminated (or 'all' for all sessions) */
    sessionId: string;
    /** Number of sessions deleted */
    sessionsDeleted: number;
}

// =============================================================================
// Strictly-Typed Audit Entry Variants
// =============================================================================

export interface LoginSuccessEntry extends Omit<AuditLogEntry, 'action' | 'details'> {
    action: 'LOGIN_SUCCESS';
    details: LoginDetails;
}

export interface LoginFailureEntry extends Omit<AuditLogEntry, 'action' | 'details'> {
    action: 'LOGIN_FAILURE';
    details: LoginDetails;
}

export interface TokenIssuedEntry extends Omit<AuditLogEntry, 'action' | 'details'> {
    action: 'TOKEN_ISSUED';
    details: TokenIssuedDetails;
}

export interface TokenRevokedEntry extends Omit<AuditLogEntry, 'action' | 'details'> {
    action: 'TOKEN_REVOKED';
    details: TokenRevokedDetails;
}

export interface SAMLAssertionEntry extends Omit<AuditLogEntry, 'action' | 'details'> {
    action: 'SAML_ASSERTION_RECEIVED';
    details: SAMLAssertionDetails;
}

export interface AuthSessionCreatedEntry extends Omit<AuditLogEntry, 'action' | 'details'> {
    action: 'AUTH_SESSION_CREATED';
    details: AuthSessionCreatedDetails;
}

export interface AuthCodeIssuedEntry extends Omit<AuditLogEntry, 'action' | 'details'> {
    action: 'AUTH_CODE_ISSUED';
    details: AuthCodeIssuedDetails;
}

export interface AuthCodeExchangedEntry extends Omit<AuditLogEntry, 'action' | 'details'> {
    action: 'AUTH_CODE_EXCHANGED';
    details: AuthCodeExchangedDetails;
}

export interface TokenRefreshedEntry extends Omit<AuditLogEntry, 'action' | 'details'> {
    action: 'TOKEN_REFRESHED';
    details: TokenRefreshedDetails;
}

export interface TokenIntrospectedEntry extends Omit<AuditLogEntry, 'action' | 'details'> {
    action: 'TOKEN_INTROSPECTED';
    details: TokenIntrospectedDetails;
}

export interface ClientAuthenticatedEntry extends Omit<AuditLogEntry, 'action' | 'details'> {
    action: 'CLIENT_AUTHENTICATED';
    details: ClientAuthenticatedDetails;
}

export interface ClientAuthFailedEntry extends Omit<AuditLogEntry, 'action' | 'details'> {
    action: 'CLIENT_AUTH_FAILED';
    details: ClientAuthFailedDetails;
}

export interface LogoutEntry extends Omit<AuditLogEntry, 'action' | 'details'> {
    action: 'LOGOUT';
    details: LogoutDetails;
}

/** Union of all strictly-typed audit entries */
export type StrictAuditLogEntry =
    | LoginSuccessEntry
    | LoginFailureEntry
    | LogoutEntry
    | TokenIssuedEntry
    | TokenRevokedEntry
    | TokenRefreshedEntry
    | TokenIntrospectedEntry
    | AuthSessionCreatedEntry
    | AuthCodeIssuedEntry
    | AuthCodeExchangedEntry
    | SAMLAssertionEntry
    | ClientAuthenticatedEntry
    | ClientAuthFailedEntry;

// =============================================================================
// Audit Logger Interface (Contract for Implementation)
// =============================================================================

/**
 * Contract for the AuditLogger utility class.
 * Implementations must ensure all entries are written to CloudWatch.
 */
export interface AuditLogger {
    /**
     * Log an audit event with flexible details.
     * requestId and ip are optional - they will be filled from context if not provided.
     */
    log(entry: Omit<AuditLogEntry, 'level' | 'timestamp'>): void;

    /**
     * Log a strictly-typed audit event.
     * requestId and ip are optional - they will be filled from context if not provided.
     */
    logStrict(entry: Omit<StrictAuditLogEntry, 'level' | 'timestamp'>): void;

    /**
     * Create a child logger with preset context (requestId, ip).
     */
    child(context: { requestId: string; ip: string }): AuditLogger;
}
