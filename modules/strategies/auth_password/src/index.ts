/**
 * OAuth Server - Password Authentication Strategy
 *
 * Module exports for the password authentication strategy.
 * This file provides a clean interface for testing and potential code sharing.
 *
 * Note: Logging and CSRF utilities are provided by @oauth-server/shared.
 */

// Types
export type {
    LoginSessionItem,
    UserItem,
    UserProfile,
    UserStatus,
    LoginEnvConfig,
    VerifyEnvConfig,
    LoginFormData,
    LoginFormParams,
    LambdaResponse,
} from './types';

// Configuration
export { getLoginConfig, getVerifyConfig, clearConfigCache } from './config';

// Database
export {
    getDocClient,
    getSession,
    updateSessionWithUser,
    getUserByEmail,
    incrementFailedAttempts,
    resetFailedAttempts,
    lockUserAccount,
} from './db';

// Form parsing
export { parseFormBody } from './form-parser';

// Responses
export {
    htmlResponse,
    errorResponse,
    redirect,
    redirectToLoginWithError,
} from './responses';

// Template
export { getErrorMessage, renderLoginForm } from './template';

// Validation
export {
    isSessionExpired,
    isAccountLocked,
    calculateLockoutExpiry,
} from './validation';

// Handlers
export { handler as loginHandler } from './login-handler';
export { handler as verifyHandler } from './verify-handler';
