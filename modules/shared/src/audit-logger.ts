/**
 * OAuth Server - Audit Logger
 *
 * SOC2-compliant structured JSON logging to CloudWatch.
 * Implements the AuditLogger interface from shared_types/audit.d.ts.
 *
 * Design Principles:
 * - All audit events are JSON-formatted for CloudWatch Logs Insights queries
 * - Every security-relevant action produces an audit entry
 * - Request context (requestId, IP) is captured for traceability
 * - Convenience methods ensure consistent event structure
 *
 * SOC2 Compliance:
 * - All authentication events are logged (LOGIN_SUCCESS, LOGIN_FAILURE)
 * - Token lifecycle is tracked (TOKEN_ISSUED, TOKEN_REVOKED, TOKEN_REFRESHED)
 * - Authorization flow is auditable (AUTH_SESSION_CREATED, AUTH_CODE_ISSUED)
 *
 * @see SOC2 CC6.1 - Logical and Physical Access Controls
 * @see SOC2 CC7.2 - System Operations Monitoring
 */

import type { APIGatewayProxyEventV2, Context } from 'aws-lambda';
import type {
    AuditActor,
    AuditLogEntry,
    AuditLogger as IAuditLogger,
    StrictAuditLogEntry,
} from '../../shared_types/audit';

// =============================================================================
// Request Context Interface
// =============================================================================

export interface AuditContext {
    /** AWS Request ID for tracing */
    requestId: string;
    /** Source IP address */
    ip: string;
    /** User agent string */
    userAgent?: string;
}

// =============================================================================
// Audit Logger Implementation
// =============================================================================

/**
 * AuditLogger provides structured JSON logging for SOC2 compliance.
 * All output goes to console (which Lambda routes to CloudWatch).
 */
export class AuditLogger implements IAuditLogger {
    private readonly context: AuditContext;

    constructor(context: AuditContext) {
        this.context = context;
    }

    /**
     * Log an audit event with flexible details.
     */
    log(
        entry: Omit<AuditLogEntry, 'level' | 'timestamp'>
    ): void {
        const logEntry: AuditLogEntry = {
            level: 'AUDIT',
            timestamp: new Date().toISOString(),
            requestId: entry.requestId || this.context.requestId,
            action: entry.action,
            ip: entry.ip || this.context.ip,
            actor: entry.actor,
            details: entry.details,
        };

        // Output as JSON to console (CloudWatch will capture this)
        console.log(JSON.stringify(logEntry));
    }

    /**
     * Log a strictly-typed audit event.
     */
    logStrict(
        entry: Omit<StrictAuditLogEntry, 'level' | 'timestamp'>
    ): void {
        const logEntry = {
            level: 'AUDIT' as const,
            timestamp: new Date().toISOString(),
            requestId: entry.requestId || this.context.requestId,
            action: entry.action,
            ip: entry.ip || this.context.ip,
            actor: entry.actor,
            details: entry.details,
        };

        console.log(JSON.stringify(logEntry));
    }

    /**
     * Create a child logger with preset context.
     */
    child(context: { requestId: string; ip: string }): AuditLogger {
        return new AuditLogger({
            requestId: context.requestId,
            ip: context.ip,
            userAgent: this.context.userAgent,
        });
    }

    // ---------------------------------------------------------------------------
    // Convenience Methods
    // ---------------------------------------------------------------------------

    /**
     * Log a successful login event.
     */
    loginSuccess(
        actor: AuditActor,
        details: { method: 'password' | 'saml'; email?: string; mfaUsed?: boolean; mfaPending?: boolean }
    ): void {
        this.logStrict({
            requestId: this.context.requestId,
            action: 'LOGIN_SUCCESS',
            ip: this.context.ip,
            actor,
            details,
        });
    }

    /**
     * Log a failed login attempt.
     */
    loginFailure(
        details: { method: 'password' | 'saml'; email?: string; reason: string }
    ): void {
        this.logStrict({
            requestId: this.context.requestId,
            action: 'LOGIN_FAILURE',
            ip: this.context.ip,
            actor: { type: 'ANONYMOUS' },
            details,
        });
    }

    /**
     * Log a token issuance event.
     */
    tokenIssued(
        actor: AuditActor,
        details: {
            tokenType: 'access_token' | 'refresh_token' | 'id_token';
            clientId: string;
            scopes: string[];
            expiresAt: string;
            grantType: string;
        }
    ): void {
        this.logStrict({
            requestId: this.context.requestId,
            action: 'TOKEN_ISSUED',
            ip: this.context.ip,
            actor,
            details,
        });
    }

    /**
     * Log a token revocation event.
     */
    tokenRevoked(
        actor: AuditActor,
        details: {
            tokenType: 'access_token' | 'refresh_token';
            reason: 'user_logout' | 'admin_action' | 'rotation' | 'expiration';
            tokenHint?: string;
        }
    ): void {
        this.logStrict({
            requestId: this.context.requestId,
            action: 'TOKEN_REVOKED',
            ip: this.context.ip,
            actor,
            details,
        });
    }

    /**
     * Log an authorization session creation event.
     */
    authSessionCreated(
        actor: AuditActor,
        details: {
            sessionId: string;
            scope: string;
            redirectUri: string;
        }
    ): void {
        this.log({
            requestId: this.context.requestId,
            action: 'AUTH_SESSION_CREATED',
            ip: this.context.ip,
            actor,
            details,
        });
    }

    /**
     * Log an authorization code issuance event.
     */
    authCodeIssued(
        actor: AuditActor,
        details: {
            clientId: string;
            scopes: string[];
            expiresAt: string;
        }
    ): void {
        this.log({
            requestId: this.context.requestId,
            action: 'AUTH_CODE_ISSUED',
            ip: this.context.ip,
            actor,
            details,
        });
    }

    /**
     * Log an authorization code exchange event.
     */
    authCodeExchanged(
        actor: AuditActor,
        details: {
            clientId: string;
            grantType: 'authorization_code';
        }
    ): void {
        this.log({
            requestId: this.context.requestId,
            action: 'AUTH_CODE_EXCHANGED',
            ip: this.context.ip,
            actor,
            details,
        });
    }

    /**
     * Log a token refresh event.
     */
    tokenRefreshed(
        actor: AuditActor,
        details: {
            clientId: string;
            scopes: string[];
            tokenRotated: boolean;
        }
    ): void {
        this.log({
            requestId: this.context.requestId,
            action: 'TOKEN_REFRESHED',
            ip: this.context.ip,
            actor,
            details,
        });
    }

    /**
     * Log a token introspection event.
     */
    tokenIntrospected(
        actor: AuditActor,
        details: {
            active: boolean;
            tokenType: 'access_token' | 'refresh_token';
            tokenClientId?: string;
            requestingClientId: string;
        }
    ): void {
        this.logStrict({
            requestId: this.context.requestId,
            action: 'TOKEN_INTROSPECTED',
            ip: this.context.ip,
            actor,
            details,
        });
    }

    /**
     * Log a client authentication event.
     */
    clientAuthenticated(
        details: {
            clientId: string;
            method: 'client_secret_basic' | 'client_secret_post' | 'private_key_jwt' | 'none';
        }
    ): void {
        this.logStrict({
            requestId: this.context.requestId,
            action: 'CLIENT_AUTHENTICATED',
            ip: this.context.ip,
            actor: { type: 'CLIENT', clientId: details.clientId },
            details,
        });
    }

    /**
     * Log a client authentication failure event.
     */
    clientAuthFailed(
        details: {
            clientId?: string;
            reason: 'invalid_client' | 'invalid_secret' | 'expired_credentials' | 'unknown_client';
        }
    ): void {
        this.logStrict({
            requestId: this.context.requestId,
            action: 'CLIENT_AUTH_FAILED',
            ip: this.context.ip,
            actor: { type: 'ANONYMOUS' },
            details,
        });
    }

    /**
     * Log a SAML assertion received event.
     */
    samlAssertionReceived(
        actor: AuditActor,
        details: {
            issuer: string;
            assertionId: string;
            valid: boolean;
            validationError?: string;
            nameId?: string;
        }
    ): void {
        this.logStrict({
            requestId: this.context.requestId,
            action: 'SAML_ASSERTION_RECEIVED',
            ip: this.context.ip,
            actor,
            details,
        });
    }

    /**
     * Log a user update event (SCIM or self-service).
     */
    userUpdated(
        actor: AuditActor,
        details: {
            userId: string;
            updatedFields: string[];
            selfService?: boolean;
        }
    ): void {
        this.log({
            requestId: this.context.requestId,
            action: 'USER_UPDATED',
            ip: this.context.ip,
            actor,
            details,
        });
    }

    /**
     * Log a generic audit event.
     * Use this for actions that don't have a dedicated convenience method.
     */
    audit(
        action: AuditLogEntry['action'],
        actor: AuditActor,
        details: Record<string, unknown>
    ): void {
        this.log({
            requestId: this.context.requestId,
            action,
            ip: this.context.ip,
            actor,
            details,
        });
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/**
 * Extract audit context from an API Gateway HTTP API v2 request.
 * Use this to create an AuditLogger with request-specific context.
 *
 * @example
 * ```typescript
 * export const handler = async (event: APIGatewayProxyEventV2, context: Context) => {
 *   const logger = withContext(event, context);
 *   logger.loginSuccess({ type: 'USER', sub: 'user-123' }, { method: 'password' });
 * };
 * ```
 */
export function withContext(
    event: APIGatewayProxyEventV2,
    lambdaContext?: Context
): AuditLogger {
    // Extract IP from HTTP API v2 format (headers are lowercase)
    const forwardedFor = event.headers?.['x-forwarded-for'];
    const ip = forwardedFor
        ? forwardedFor.split(',')[0].trim()
        : event.requestContext?.http?.sourceIp || 'unknown';

    // Extract request ID
    const requestId =
        lambdaContext?.awsRequestId ||
        event.requestContext?.requestId ||
        event.headers?.['x-request-id'] ||
        'unknown';

    // Extract user agent (v2 headers are lowercase)
    const userAgent = event.headers?.['user-agent'];

    return new AuditLogger({
        requestId,
        ip,
        userAgent,
    });
}

/**
 * Create an AuditLogger for system/background processes.
 */
export function createSystemLogger(processName: string): AuditLogger {
    return new AuditLogger({
        requestId: `system-${Date.now()}`,
        ip: 'internal',
        userAgent: processName,
    });
}

// =============================================================================
// General Logger (Non-Audit Structured Logging)
// =============================================================================

/** Log levels for structured logging */
export type LogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR';

interface LogEntry {
    level: LogLevel;
    timestamp: string;
    requestId: string;
    message: string;
    data?: Record<string, unknown>;
}

/**
 * General-purpose structured logger for non-audit events.
 */
export class Logger {
    private readonly requestId: string;

    constructor(requestId: string) {
        this.requestId = requestId;
    }

    private write(level: LogLevel, message: string, data?: Record<string, unknown>): void {
        const entry: LogEntry = {
            level,
            timestamp: new Date().toISOString(),
            requestId: this.requestId,
            message,
            ...(data && { data }),
        };

        console.log(JSON.stringify(entry));
    }

    debug(message: string, data?: Record<string, unknown>): void {
        this.write('DEBUG', message, data);
    }

    info(message: string, data?: Record<string, unknown>): void {
        this.write('INFO', message, data);
    }

    warn(message: string, data?: Record<string, unknown>): void {
        this.write('WARN', message, data);
    }

    error(message: string, data?: Record<string, unknown>): void {
        this.write('ERROR', message, data);
    }
}

/**
 * Create a Logger from API Gateway HTTP API v2 event context.
 */
export function createLogger(
    event: APIGatewayProxyEventV2,
    lambdaContext?: Context
): Logger {
    const requestId =
        lambdaContext?.awsRequestId ||
        event.requestContext?.requestId ||
        'unknown';

    return new Logger(requestId);
}
