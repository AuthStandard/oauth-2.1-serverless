/**
 * OAuth Server - Storage Module
 *
 * Exports all storage operations for the DynamoDB Single Table Design.
 *
 * @module storage
 */

export type { StorageAdapterConfig } from './types';

export {
    withRetry,
    withBatchRetry,
    isRetryableError,
    calculateDelay,
    sleep,
    DEFAULT_RETRY_CONFIG,
} from './retry';

export type { RetryConfig } from './retry';

export {
    getClient,
    saveClient,
} from './client-operations';

export {
    getUser,
    getUserByEmail,
    saveUser,
} from './user-operations';

export {
    getAuthCode,
    saveAuthCode,
    consumeAuthCode,
} from './auth-code-operations';

export {
    getRefreshToken,
    saveRefreshToken,
    rotateRefreshToken,
    revokeAllUserRefreshTokens,
    revokeTokenFamily,
} from './refresh-token-operations';

export {
    getLoginSession,
    saveLoginSession,
    updateLoginSessionAuth,
    deleteLoginSession,
    cleanupExpiredSessions,
} from './session-operations';

export {
    getSAMLProvider,
    saveSAMLProvider,
    deleteSAMLProvider,
    listEnabledSAMLProviders,
} from './saml-provider-operations';
