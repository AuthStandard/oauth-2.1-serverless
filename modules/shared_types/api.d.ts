/**
 * OAuth Server - Internal API Contracts
 *
 * Interfaces for communication between modules.
 * These define the PORTS in our Hexagonal Architecture.
 *
 * Design Principles:
 * - Protocol layer (OAuth) is decoupled from authentication strategies
 * - All dependencies point inward (strategies depend on ports, not vice versa)
 * - Ports are technology-agnostic interfaces
 *
 * @see https://alistair.cockburn.us/hexagonal-architecture/
 */

// =============================================================================
// Authentication Strategy Port
// =============================================================================

/**
 * Port interface that all authentication strategies must implement.
 * This allows the OAuth protocol layer to remain decoupled from
 * specific authentication mechanisms.
 */
export interface AuthenticationStrategy {
    /** Unique identifier for this strategy */
    readonly strategyId: string;

    /** Human-readable name */
    readonly displayName: string;

    /**
     * Authenticate a user with strategy-specific credentials.
     * Returns the authenticated user or throws an AuthenticationError.
     */
    authenticate(credentials: unknown): Promise<AuthenticatedUser>;

    /**
     * Check if this strategy supports the given authentication request.
     */
    supports(request: AuthenticationRequest): boolean;
}

export interface AuthenticatedUser {
    userId: string;
    email: string;
    emailVerified: boolean;
    authMethod: string;
    authTime: string;
}

export interface AuthenticationRequest {
    /** Strategy identifier (e.g., 'password', 'saml') */
    strategy: string;
    /** Strategy-specific credentials */
    credentials: unknown;
    /** Request context */
    context: RequestContext;
}

// =============================================================================
// Token Service Port
// =============================================================================

/**
 * Port interface for token operations.
 */
export interface TokenService {
    /**
     * Issue a new access token.
     */
    issueAccessToken(params: IssueTokenParams): Promise<IssuedToken>;

    /**
     * Issue a new refresh token.
     */
    issueRefreshToken(params: IssueTokenParams): Promise<IssuedToken>;

    /**
     * Validate and decode an access token.
     */
    validateAccessToken(token: string): Promise<TokenPayload>;

    /**
     * Revoke a token by its ID.
     */
    revokeToken(tokenId: string, type: 'access' | 'refresh'): Promise<void>;
}

export interface IssueTokenParams {
    clientId: string;
    userId?: string;
    scopes: string[];
    audience?: string;
}

export interface IssuedToken {
    token: string;
    tokenId: string;
    expiresIn: number;
    expiresAt: string;
}

export interface TokenPayload {
    /** JWT ID */
    jti: string;
    /** Issuer */
    iss: string;
    /** Subject (user ID) */
    sub?: string;
    /** Audience */
    aud: string | string[];
    /** Expiration time */
    exp: number;
    /** Issued at */
    iat: number;
    /** Client ID */
    client_id: string;
    /** Scopes */
    scope: string;
}

// =============================================================================
// User Repository Port
// =============================================================================

/**
 * Port interface for user data access.
 */
export interface UserRepository {
    findById(userId: string): Promise<User | null>;
    findByEmail(email: string): Promise<User | null>;
    create(user: CreateUserParams): Promise<User>;
    update(userId: string, updates: UpdateUserParams): Promise<User>;
    delete(userId: string): Promise<void>;
}

export interface User {
    userId: string;
    email: string;
    emailVerified: boolean;
    passwordHash?: string;
    profile: UserProfile;
    status: 'ACTIVE' | 'SUSPENDED' | 'PENDING_VERIFICATION';
    createdAt: string;
    updatedAt: string;
}

export interface UserProfile {
    givenName?: string;
    familyName?: string;
    picture?: string;
    locale?: string;
}

export interface CreateUserParams {
    email: string;
    passwordHash?: string;
    profile?: Partial<UserProfile>;
}

export interface UpdateUserParams {
    email?: string;
    emailVerified?: boolean;
    passwordHash?: string;
    profile?: Partial<UserProfile>;
    status?: 'ACTIVE' | 'SUSPENDED' | 'PENDING_VERIFICATION';
}

// =============================================================================
// Client Repository Port
// =============================================================================

/**
 * Port interface for OAuth client data access.
 */
export interface ClientRepository {
    findById(clientId: string): Promise<OAuthClient | null>;
    create(client: CreateClientParams): Promise<OAuthClient>;
    update(clientId: string, updates: UpdateClientParams): Promise<OAuthClient>;
    delete(clientId: string): Promise<void>;
    validateSecret(clientId: string, secret: string): Promise<boolean>;
}

export interface OAuthClient {
    clientId: string;
    clientName: string;
    clientType: 'PUBLIC' | 'CONFIDENTIAL';
    redirectUris: string[];
    grantTypes: string[];
    allowedScopes: string[];
    tokenLifetimes: {
        accessToken: number;
        refreshToken: number;
        authorizationCode: number;
    };
    createdAt: string;
    updatedAt: string;
}

export interface CreateClientParams {
    clientName: string;
    clientType: 'PUBLIC' | 'CONFIDENTIAL';
    clientSecret?: string;
    redirectUris: string[];
    grantTypes?: string[];
    allowedScopes?: string[];
}

export interface UpdateClientParams {
    clientName?: string;
    redirectUris?: string[];
    grantTypes?: string[];
    allowedScopes?: string[];
}

// =============================================================================
// Request Context
// =============================================================================

export interface RequestContext {
    requestId: string;
    ipAddress: string;
    userAgent?: string;
    correlationId?: string;
}
