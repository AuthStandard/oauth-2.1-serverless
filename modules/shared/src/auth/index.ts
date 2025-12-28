/**
 * OAuth 2.1 Authentication Utilities
 *
 * Shared authentication modules for OAuth 2.1 protocol endpoints.
 *
 * @module shared/auth
 */

export {
    authenticateClient,
    extractClientCredentials,
    verifyClientSecret,
} from './client-auth';

export type {
    ClientItem,
    ClientCredentials,
    ClientAuthResult,
} from './client-auth';
