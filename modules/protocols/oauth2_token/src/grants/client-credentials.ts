/**
 * OAuth 2.1 Client Credentials Grant Handler
 *
 * Implements OAuth 2.1 Section 4.2 for machine-to-machine authentication.
 *
 * Use Cases:
 * - Backend service-to-service communication
 * - Scheduled jobs accessing protected APIs
 * - Microservice authentication
 *
 * Flow:
 * 1. Authenticate client (required - confidential clients only)
 * 2. Validate DPoP proof if present (RFC 9449)
 * 3. Verify client type is CONFIDENTIAL
 * 4. Verify client is authorized for client_credentials grant
 * 5. Validate requested scope against client's allowed scopes
 * 6. Generate access token (client is the subject)
 *
 * Security Notes:
 * - Only confidential clients can use this grant (OAuth 2.1 Section 4.2)
 * - No refresh token is issued (Section 4.2.1)
 * - Client acts on its own behalf, not on behalf of a user
 * - DPoP sender-constrained tokens supported (RFC 9449)
 *
 * @module oauth2_token/grants/client-credentials
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-14#section-4.2
 * @see https://datatracker.ietf.org/doc/html/rfc9449
 */

import type { APIGatewayProxyResultV2 } from 'aws-lambda';
import type { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { randomUUID } from 'node:crypto';
import { AuditLogger, Logger } from '@oauth-server/shared';
import { createSigner } from '../signer';
import { tokenResponse, errorResponse } from '../response';
import { validateRequestedScope } from '../scope';
import { authenticateClient, extractClientCredentials } from '../client-auth';
import { handleDPoP, buildTokenEndpointUrl } from '../dpop-handler';
import type { TokenRequestParams, EnvConfig } from '../types';

// =============================================================================
// Grant Handler
// =============================================================================

/**
 * Handle client_credentials grant type.
 *
 * @param params - Parsed token request parameters
 * @param authHeader - Authorization header for client authentication
 * @param config - Environment configuration
 * @param client - DynamoDB document client
 * @param requestId - AWS request ID for tracing
 * @param ip - Client IP address for audit logging
 * @param dpopHeader - DPoP header value (optional, for sender-constrained tokens)
 * @returns Token response or error response
 */
export async function handleClientCredentialsGrant(
    params: TokenRequestParams,
    authHeader: string | undefined,
    config: EnvConfig,
    client: DynamoDBDocumentClient,
    requestId: string,
    ip: string,
    dpopHeader?: string
): Promise<APIGatewayProxyResultV2> {
    const log = new Logger(requestId);
    const audit = new AuditLogger({ requestId, ip });

    // -------------------------------------------------------------------------
    // Step 1: Verify Client Authentication Present
    // Client credentials grant MUST include client authentication
    // -------------------------------------------------------------------------
    const { clientSecret } = extractClientCredentials(params, authHeader);
    if (!clientSecret) {
        return errorResponse(400, 'invalid_request', 'Client credentials grant requires client authentication');
    }

    // -------------------------------------------------------------------------
    // Step 2: Authenticate Client
    // -------------------------------------------------------------------------
    const clientAuth = await authenticateClient(params, authHeader, client, config.tableName);
    if (!clientAuth.valid) {
        return clientAuth.error!;
    }

    const clientItem = clientAuth.clientItem!;

    // -------------------------------------------------------------------------
    // Step 3: DPoP Validation (RFC 9449)
    // -------------------------------------------------------------------------
    const dpopResult = await handleDPoP({
        dpopHeader,
        httpMethod: 'POST',
        tokenEndpointUrl: buildTokenEndpointUrl(config.issuer),
        tableName: config.tableName,
        dbClient: client,
        logger: log,
    });

    if (!dpopResult.valid) {
        return errorResponse(400, dpopResult.errorCode || 'invalid_dpop_proof', dpopResult.errorDescription);
    }

    // -------------------------------------------------------------------------
    // Step 4: Verify Client Type (OAuth 2.1 Section 4.2)
    // Only confidential clients can use client_credentials grant
    // -------------------------------------------------------------------------
    if (clientItem.clientType !== 'CONFIDENTIAL') {
        log.warn('Public client attempted client_credentials grant', { clientId: clientItem.clientId });
        return errorResponse(401, 'unauthorized_client', 'Public clients cannot use client_credentials grant');
    }

    // -------------------------------------------------------------------------
    // Step 5: Verify Grant Type Allowed
    // -------------------------------------------------------------------------
    if (!clientItem.grantTypes.includes('client_credentials')) {
        log.warn('Client not authorized for client_credentials grant', { clientId: clientItem.clientId });
        return errorResponse(401, 'unauthorized_client', 'Client is not authorized for this grant type');
    }

    // -------------------------------------------------------------------------
    // Step 6: Validate Scope
    // -------------------------------------------------------------------------
    const scopeValidation = validateRequestedScope(params.scope, clientItem.allowedScopes);
    if (!scopeValidation.valid) {
        return scopeValidation.error;
    }
    const grantedScope = scopeValidation.scope;

    // -------------------------------------------------------------------------
    // Step 7: Generate Access Token
    // For client_credentials, the client is both the subject and the client
    // Include DPoP thumbprint if DPoP was used
    // -------------------------------------------------------------------------
    const signer = createSigner();
    const jti = randomUUID();
    const accessTokenTtl = clientItem.tokenLifetimes?.accessToken || config.accessTokenTtl;

    const accessToken = await signer.createAccessToken({
        issuer: config.issuer,
        sub: clientItem.clientId,
        clientId: clientItem.clientId,
        scope: grantedScope,
        audience: clientItem.clientId,
        expiresIn: accessTokenTtl,
        jti,
        dpopThumbprint: dpopResult.thumbprint,
    });

    // Audit token issuance
    const expiresAt = new Date(Date.now() + accessTokenTtl * 1000).toISOString();
    audit.tokenIssued(
        { type: 'CLIENT', clientId: clientItem.clientId },
        {
            tokenType: 'access_token',
            clientId: clientItem.clientId,
            scopes: grantedScope.split(' '),
            expiresAt,
            grantType: 'client_credentials',
            ...(dpopResult.dpopUsed && { dpopBound: true }),
        }
    );

    log.info('Client credentials token issued', {
        clientId: clientItem.clientId,
        scope: grantedScope,
        dpopBound: dpopResult.dpopUsed,
    });

    // -------------------------------------------------------------------------
    // Step 8: Build Response (RFC 9449 Section 5)
    // Note: No refresh_token per OAuth 2.1 Section 4.2.1
    // -------------------------------------------------------------------------
    const tokenType = dpopResult.dpopUsed ? 'DPoP' : 'Bearer';
    return tokenResponse({
        access_token: accessToken,
        token_type: tokenType,
        expires_in: accessTokenTtl,
        scope: grantedScope,
    });
}
