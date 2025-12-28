/**
 * OAuth 2.1 Token Endpoint - Lambda Handler
 *
 * Implements POST /token per OAuth 2.1 (draft-ietf-oauth-v2-1-14) Section 3.2.
 *
 * Supported Grant Types:
 * - authorization_code (Section 4.1.3): Exchange auth code for tokens with mandatory PKCE
 * - refresh_token (Section 4.3): Obtain new tokens with mandatory rotation
 * - client_credentials (Section 4.2): Machine-to-machine authentication
 *
 * Security Features:
 * - PKCE mandatory for all authorization_code grants (OAuth 2.1 requirement)
 * - Refresh token rotation with family tracking (replay attack detection)
 * - Constant-time secret comparison (timing attack prevention)
 * - Duplicate parameter rejection (Section 3.1)
 * - CORS support for browser-based clients
 * - SOC2-compliant structured audit logging
 *
 * Request Format:
 * - Method: POST (or OPTIONS for CORS preflight)
 * - Content-Type: application/x-www-form-urlencoded
 * - Authentication: HTTP Basic (recommended) or POST body credentials
 *
 * @module oauth2_token
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-14#section-3.2
 */

import type { APIGatewayProxyEventV2, APIGatewayProxyResultV2, Context } from 'aws-lambda';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { createLogger, serverError } from '@oauth-server/shared';
import { errorResponse, withCors, corsPreflightResponse } from './response';
import {
    handleAuthorizationCodeGrant,
    handleRefreshTokenGrant,
    handleClientCredentialsGrant,
} from './grants';
import type { TokenRequestParams, EnvConfig } from './types';

// =============================================================================
// Constants
// =============================================================================

/**
 * Supported OAuth 2.1 grant types.
 * Per OAuth 2.1, these are the only standard grant types (implicit and ROPC removed).
 */
const SUPPORTED_GRANT_TYPES = [
    'authorization_code',
    'refresh_token',
    'client_credentials',
] as const;

type SupportedGrantType = (typeof SUPPORTED_GRANT_TYPES)[number];

// =============================================================================
// Environment Configuration
// =============================================================================

/**
 * Load and validate environment configuration.
 * All values come from Terraform - no hardcoded defaults.
 *
 * @throws Error if any required environment variable is missing or invalid
 */
function getEnvConfig(): EnvConfig {
    const tableName = process.env.TABLE_NAME;
    const issuer = process.env.ISSUER;
    const keyId = process.env.KEY_ID;
    const kmsKeyId = process.env.KMS_KEY_ID;
    const accessTokenTtl = parseInt(process.env.ACCESS_TOKEN_TTL || '', 10);
    const idTokenTtl = parseInt(process.env.ID_TOKEN_TTL || '', 10);
    const refreshTokenTtl = parseInt(process.env.REFRESH_TOKEN_TTL || '', 10);
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',').map(o => o.trim()) || [];

    if (!tableName) throw new Error('TABLE_NAME environment variable is required');
    if (!issuer) throw new Error('ISSUER environment variable is required');
    if (!keyId) throw new Error('KEY_ID environment variable is required');
    if (!kmsKeyId) throw new Error('KMS_KEY_ID environment variable is required');
    if (isNaN(accessTokenTtl) || accessTokenTtl <= 0) throw new Error('ACCESS_TOKEN_TTL must be a positive integer');
    if (isNaN(idTokenTtl) || idTokenTtl <= 0) throw new Error('ID_TOKEN_TTL must be a positive integer');
    if (isNaN(refreshTokenTtl) || refreshTokenTtl <= 0) throw new Error('REFRESH_TOKEN_TTL must be a positive integer');

    return { tableName, issuer, keyId, accessTokenTtl, idTokenTtl, refreshTokenTtl, allowedOrigins };
}

// =============================================================================
// DynamoDB Client (Singleton)
// =============================================================================

/** Cached DynamoDB client for Lambda warm starts */
let docClient: DynamoDBDocumentClient | null = null;

/**
 * Get or create DynamoDB document client.
 * Uses singleton pattern to reuse connections across Lambda invocations.
 */
function getDocClient(): DynamoDBDocumentClient {
    if (!docClient) {
        const client = new DynamoDBClient({});
        docClient = DynamoDBDocumentClient.from(client, {
            marshallOptions: { removeUndefinedValues: true },
        });
    }
    return docClient;
}

// =============================================================================
// CORS Helpers
// =============================================================================

/**
 * Escape special regex characters except asterisk.
 */
function escapeRegexExceptWildcard(str: string): string {
    return str.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Check if the request origin is allowed for CORS.
 *
 * @param origin - The Origin header from the request
 * @param allowedOrigins - List of allowed origins from config
 * @returns The allowed origin or undefined if not allowed
 */
function getAllowedOrigin(origin: string | undefined, allowedOrigins: string[]): string | undefined {
    if (!origin) {
        return undefined;
    }

    // If no origins configured, allow all (for development)
    if (allowedOrigins.length === 0) {
        return origin;
    }

    // Check if origin is in allowed list
    if (allowedOrigins.includes(origin)) {
        return origin;
    }

    // Check for wildcard patterns (e.g., https://*.example.com)
    for (const allowed of allowedOrigins) {
        if (allowed.includes('*')) {
            // Escape regex special chars, then replace * with .*
            const escaped = escapeRegexExceptWildcard(allowed);
            const pattern = new RegExp('^' + escaped.replace(/\*/g, '.*') + '$');
            if (pattern.test(origin)) {
                return origin;
            }
        }
    }

    return undefined;
}

// =============================================================================
// Duplicate Parameter Detection
// =============================================================================

/**
 * Check for duplicate parameters in the request body.
 *
 * Per OAuth 2.1 Section 3.1, request parameters MUST NOT be included
 * more than once. This prevents parameter pollution attacks.
 *
 * @param body - Raw request body
 * @returns Array of duplicate parameter names, empty if none
 */
function findDuplicateParams(body: string): string[] {
    if (!body) {
        return [];
    }

    const paramCounts = new Map<string, number>();
    const pairs = body.split('&');

    for (const pair of pairs) {
        const [key] = pair.split('=');
        if (key) {
            const decodedKey = decodeURIComponent(key);
            paramCounts.set(decodedKey, (paramCounts.get(decodedKey) || 0) + 1);
        }
    }

    const duplicates: string[] = [];
    for (const [key, count] of paramCounts) {
        if (count > 1) {
            duplicates.push(key);
        }
    }

    return duplicates;
}

// =============================================================================
// Request Parsing
// =============================================================================

/**
 * Parse form-urlencoded request body into token request parameters.
 *
 * Per OAuth 2.1 Section 3.2.2:
 * - Content-Type MUST be application/x-www-form-urlencoded
 * - Parameters are UTF-8 encoded
 *
 * @param event - API Gateway HTTP API v2 event
 * @returns Parsed token request parameters
 */
function parseRequestBody(event: APIGatewayProxyEventV2): TokenRequestParams {
    let body = event.body || '';
    if (event.isBase64Encoded) {
        body = Buffer.from(body, 'base64').toString('utf-8');
    }

    const params = new URLSearchParams(body);

    return {
        grantType: params.get('grant_type') || '',
        code: params.get('code') || undefined,
        redirectUri: params.get('redirect_uri') || undefined,
        codeVerifier: params.get('code_verifier') || undefined,
        clientId: params.get('client_id') || undefined,
        clientSecret: params.get('client_secret') || undefined,
        refreshToken: params.get('refresh_token') || undefined,
        scope: params.get('scope') || undefined,
    };
}

/**
 * Get raw request body for duplicate parameter detection.
 */
function getRawBody(event: APIGatewayProxyEventV2): string {
    let body = event.body || '';
    if (event.isBase64Encoded) {
        body = Buffer.from(body, 'base64').toString('utf-8');
    }
    return body;
}

/**
 * Extract client IP address from API Gateway HTTP API v2 request.
 */
function getSourceIp(event: APIGatewayProxyEventV2): string {
    const forwardedFor = event.headers?.['x-forwarded-for'];
    if (forwardedFor) {
        return forwardedFor.split(',')[0].trim();
    }
    return event.requestContext.http.sourceIp || 'unknown';
}

// =============================================================================
// Lambda Handler
// =============================================================================

/**
 * OAuth 2.1 Token Endpoint handler.
 *
 * Processes POST /token requests and dispatches to appropriate grant handler.
 * Also handles OPTIONS requests for CORS preflight.
 *
 * @param event - API Gateway proxy event
 * @param context - Lambda context
 * @returns Token response or error response
 */
export const handler = async (
    event: APIGatewayProxyEventV2,
    context: Context
): Promise<APIGatewayProxyResultV2> => {
    const logger = createLogger(event, context);
    const requestId = context.awsRequestId;
    const ip = getSourceIp(event);

    // Extract origin early for CORS headers on error responses (v2 headers are lowercase)
    const origin = event.headers?.['origin'];
    let allowedOrigin: string | undefined;

    try {
        const config = getEnvConfig();
        allowedOrigin = getAllowedOrigin(origin, config.allowedOrigins);

        const method = event.requestContext.http.method;

        // Handle CORS preflight requests
        if (method === 'OPTIONS') {
            logger.info('CORS preflight request received');
            return corsPreflightResponse(allowedOrigin);
        }

        logger.info('Token request received', { path: event.requestContext.http.path, method });

        // Validate HTTP method
        if (method !== 'POST') {
            const response = errorResponse(405, 'invalid_request', 'Method not allowed. Use POST.');
            return allowedOrigin ? withCors(response, allowedOrigin) : response;
        }

        // Validate Content-Type per OAuth 2.1 Section 3.2.2 (v2 headers are lowercase)
        const contentType = event.headers?.['content-type'] || '';
        if (!contentType.includes('application/x-www-form-urlencoded')) {
            const response = errorResponse(400, 'invalid_request', 'Content-Type must be application/x-www-form-urlencoded');
            return allowedOrigin ? withCors(response, allowedOrigin) : response;
        }

        // Check for duplicate parameters (OAuth 2.1 Section 3.1)
        const rawBody = getRawBody(event);
        const duplicates = findDuplicateParams(rawBody);
        if (duplicates.length > 0) {
            logger.warn('Duplicate parameters detected', { duplicates });
            const response = errorResponse(400, 'invalid_request', `Duplicate parameters not allowed: ${duplicates.join(', ')}`);
            return allowedOrigin ? withCors(response, allowedOrigin) : response;
        }

        const params = parseRequestBody(event);

        // grant_type is always required per OAuth 2.1 Section 3.2.2
        if (!params.grantType) {
            const response = errorResponse(400, 'invalid_request', 'Missing required parameter: grant_type');
            return allowedOrigin ? withCors(response, allowedOrigin) : response;
        }

        if (!SUPPORTED_GRANT_TYPES.includes(params.grantType as SupportedGrantType)) {
            logger.warn('Unsupported grant type requested', { grantType: params.grantType });
            const response = errorResponse(400, 'unsupported_grant_type', `Grant type '${params.grantType}' is not supported`);
            return allowedOrigin ? withCors(response, allowedOrigin) : response;
        }

        const client = getDocClient();
        // v2 headers are lowercase
        const authHeader = event.headers?.['authorization'];
        const dpopHeader = event.headers?.['dpop'];

        // Dispatch to appropriate grant handler
        let response: APIGatewayProxyResultV2;
        switch (params.grantType as SupportedGrantType) {
            case 'authorization_code':
                response = await handleAuthorizationCodeGrant(params, authHeader, config, client, requestId, ip, dpopHeader);
                break;
            case 'refresh_token':
                response = await handleRefreshTokenGrant(params, authHeader, config, client, requestId, ip, dpopHeader);
                break;
            case 'client_credentials':
                response = await handleClientCredentialsGrant(params, authHeader, config, client, requestId, ip, dpopHeader);
                break;
        }

        // Add CORS headers if origin is allowed
        return allowedOrigin ? withCors(response, allowedOrigin) : response;
    } catch (err) {
        const e = err as Error;
        logger.error('Token endpoint error', { error: e.message, stack: e.stack });
        const response = serverError('An unexpected error occurred');
        return allowedOrigin ? withCors(response, allowedOrigin) : response;
    }
};
