/**
 * OAuth Server - Rate Limiting Utilities
 *
 * Provides rate limiting awareness for Lambda handlers.
 * Works with API Gateway throttling and provides application-level controls.
 *
 * Architecture:
 * - Primary rate limiting is handled by API Gateway (configured via Terraform)
 * - This module provides application-level rate limit detection and response helpers
 * - DynamoDB-based rate limiting for fine-grained per-user/per-client controls
 *
 * Rate Limit Strategy:
 * - API Gateway: Global burst/rate limits (first line of defense)
 * - Application: Per-client, per-user, per-IP limits for sensitive operations
 * - DynamoDB: Sliding window counters for persistent rate tracking
 *
 * @see RFC 6585 Section 4 - 429 Too Many Requests
 * @see RFC 9110 Section 10.2.4 - Retry-After header
 */

import type { APIGatewayProxyResultV2 } from 'aws-lambda';

// =============================================================================
// Types
// =============================================================================

/**
 * Structured API Gateway response (excludes string shorthand).
 * Used for functions that need to manipulate response headers.
 */
type StructuredResponse = Exclude<APIGatewayProxyResultV2, string>;

// =============================================================================
// Types
// =============================================================================

/**
 * Rate limit configuration for a specific operation.
 */
export interface RateLimitConfig {
    /** Maximum requests allowed in the window */
    maxRequests: number;
    /** Time window in seconds */
    windowSeconds: number;
    /** Optional: Different limits for authenticated vs anonymous */
    authenticatedMultiplier?: number;
}

/**
 * Rate limit check result.
 */
export interface RateLimitResult {
    /** Whether the request is allowed */
    allowed: boolean;
    /** Remaining requests in current window */
    remaining: number;
    /** Seconds until the window resets */
    resetInSeconds: number;
    /** Total limit for the window */
    limit: number;
}

/**
 * Rate limit key components for building cache keys.
 */
export interface RateLimitKey {
    /** Operation identifier (e.g., 'token', 'authorize', 'login') */
    operation: string;
    /** Client identifier (optional) */
    clientId?: string;
    /** User identifier (optional) */
    userId?: string;
    /** IP address (optional) */
    ip?: string;
}

// =============================================================================
// Default Configurations
// =============================================================================

/**
 * Default rate limits for OAuth operations.
 * These are application-level limits in addition to API Gateway throttling.
 *
 * Security Rationale:
 * - Token endpoint: Moderate limit to prevent credential stuffing
 * - Login attempts: Strict limit to prevent brute force
 * - Authorization: Higher limit as it's user-initiated
 * - Introspection: Higher limit for resource servers
 */
export const DefaultRateLimits: Record<string, RateLimitConfig> = {
    /** Token endpoint: 100 requests per minute per client */
    token: {
        maxRequests: 100,
        windowSeconds: 60,
    },
    /** Login attempts: 5 per minute per IP (brute force protection) */
    login: {
        maxRequests: 5,
        windowSeconds: 60,
    },
    /** Failed login: 10 per 15 minutes per IP (lockout threshold) */
    loginFailure: {
        maxRequests: 10,
        windowSeconds: 900,
    },
    /** Authorization: 30 per minute per user */
    authorize: {
        maxRequests: 30,
        windowSeconds: 60,
    },
    /** Token introspection: 1000 per minute per client */
    introspect: {
        maxRequests: 1000,
        windowSeconds: 60,
    },
    /** Token revocation: 100 per minute per client */
    revoke: {
        maxRequests: 100,
        windowSeconds: 60,
    },
};

// =============================================================================
// Rate Limit Key Generation
// =============================================================================

/**
 * Build a rate limit key for DynamoDB or cache storage.
 *
 * Key format: RATELIMIT#<operation>#<identifier>
 *
 * @param key - Rate limit key components
 * @returns Formatted key string
 */
export function buildRateLimitKey(key: RateLimitKey): string {
    const parts = ['RATELIMIT', key.operation];

    if (key.clientId) {
        parts.push(`client:${key.clientId}`);
    }
    if (key.userId) {
        parts.push(`user:${key.userId}`);
    }
    if (key.ip) {
        parts.push(`ip:${key.ip}`);
    }

    return parts.join('#');
}

// =============================================================================
// Sliding Window Counter (In-Memory for Lambda)
// =============================================================================

/**
 * In-memory sliding window counter for Lambda.
 *
 * Note: This is per-Lambda-instance and resets on cold starts.
 * For persistent rate limiting across instances, use DynamoDB.
 * This is suitable for burst protection within a single invocation context.
 */
const windowCounters = new Map<string, { count: number; windowStart: number }>();

/**
 * Check rate limit using in-memory sliding window.
 *
 * This provides basic burst protection within a Lambda instance.
 * For production, combine with DynamoDB-based persistent counters.
 *
 * @param key - Rate limit key
 * @param config - Rate limit configuration
 * @returns Rate limit check result
 */
export function checkRateLimitInMemory(
    key: string,
    config: RateLimitConfig
): RateLimitResult {
    const now = Math.floor(Date.now() / 1000);
    const windowStart = now - (now % config.windowSeconds);

    let counter = windowCounters.get(key);

    // Reset counter if window has passed
    if (!counter || counter.windowStart < windowStart) {
        counter = { count: 0, windowStart };
        windowCounters.set(key, counter);
    }

    const remaining = Math.max(0, config.maxRequests - counter.count);
    const resetInSeconds = config.windowSeconds - (now - counter.windowStart);

    if (counter.count >= config.maxRequests) {
        return {
            allowed: false,
            remaining: 0,
            resetInSeconds,
            limit: config.maxRequests,
        };
    }

    // Increment counter
    counter.count++;

    return {
        allowed: true,
        remaining: remaining - 1,
        resetInSeconds,
        limit: config.maxRequests,
    };
}

/**
 * Clean up expired window counters to prevent memory leaks.
 * Call periodically in long-running Lambda instances.
 */
export function cleanupExpiredCounters(): void {
    const now = Math.floor(Date.now() / 1000);
    const maxAge = 3600; // 1 hour

    for (const [key, counter] of windowCounters.entries()) {
        if (now - counter.windowStart > maxAge) {
            windowCounters.delete(key);
        }
    }
}

// =============================================================================
// HTTP Response Helpers
// =============================================================================

/**
 * Standard headers for rate limit responses.
 */
const RATE_LIMIT_HEADERS = {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
} as const;

/**
 * Create a 429 Too Many Requests response.
 *
 * Includes standard rate limit headers per RFC 6585 and draft-ietf-httpapi-ratelimit-headers.
 *
 * @param result - Rate limit check result
 * @param description - Optional error description
 * @returns API Gateway response
 */
export function rateLimitExceeded(
    result: RateLimitResult,
    description = 'Rate limit exceeded. Please retry later.'
): APIGatewayProxyResultV2 {
    return {
        statusCode: 429,
        headers: {
            ...RATE_LIMIT_HEADERS,
            'Retry-After': String(result.resetInSeconds),
            'X-RateLimit-Limit': String(result.limit),
            'X-RateLimit-Remaining': String(result.remaining),
            'X-RateLimit-Reset': String(Math.floor(Date.now() / 1000) + result.resetInSeconds),
        },
        body: JSON.stringify({
            error: 'too_many_requests',
            error_description: description,
            retry_after: result.resetInSeconds,
        }),
    };
}

/**
 * Add rate limit headers to a successful response.
 *
 * @param response - Original response
 * @param result - Rate limit check result
 * @returns Response with rate limit headers
 */
export function withRateLimitHeaders(
    response: StructuredResponse,
    result: RateLimitResult
): StructuredResponse {
    return {
        ...response,
        headers: {
            ...response.headers,
            'X-RateLimit-Limit': String(result.limit),
            'X-RateLimit-Remaining': String(result.remaining),
            'X-RateLimit-Reset': String(Math.floor(Date.now() / 1000) + result.resetInSeconds),
        },
    };
}

// =============================================================================
// IP Extraction Utilities
// =============================================================================

/**
 * Extract client IP from API Gateway event.
 *
 * Handles X-Forwarded-For header for requests through load balancers/proxies.
 * Takes the first IP in the chain (original client).
 *
 * @param headers - Request headers (case-insensitive lookup)
 * @param sourceIp - Source IP from request context
 * @returns Client IP address
 */
export function extractClientIp(
    headers: Record<string, string | undefined> | null | undefined,
    sourceIp?: string
): string {
    if (headers) {
        // Check X-Forwarded-For first (may contain multiple IPs)
        // Headers can be case-insensitive, check both variants
        const forwardedFor = headers['X-Forwarded-For'] ?? headers['x-forwarded-for'];
        if (forwardedFor) {
            const firstIp = forwardedFor.split(',')[0]?.trim();
            if (firstIp) {
                return firstIp;
            }
        }
    }

    return sourceIp || 'unknown';
}

/**
 * Normalize IP address for rate limiting.
 *
 * For IPv6, uses the /64 prefix to group requests from the same network.
 * This prevents bypassing rate limits by rotating through IPv6 addresses.
 *
 * @param ip - Raw IP address
 * @returns Normalized IP for rate limiting
 */
export function normalizeIpForRateLimit(ip: string): string {
    // IPv6 address - use /64 prefix
    if (ip.includes(':')) {
        const parts = ip.split(':');
        // Take first 4 segments (64 bits)
        return parts.slice(0, 4).join(':') + '::/64';
    }

    // IPv4 - use as-is
    return ip;
}
