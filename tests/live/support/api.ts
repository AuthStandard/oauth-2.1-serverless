/**
 * HTTP Client Wrappers and Assertion Helpers
 *
 * Provides consistent HTTP request handling and specialized assertions
 * for OAuth 2.1 and OIDC protocol testing.
 */

import { API_BASE_URL } from '../setup';
import * as jose from 'jose';

// =============================================================================
// Types
// =============================================================================

export interface HttpResponse<T = unknown> {
  status: number;
  statusText: string;
  headers: Headers;
  data: T;
  raw: Response;
}

export interface OIDCDiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  jwks_uri: string;
  registration_endpoint?: string;
  scopes_supported?: string[];
  response_types_supported: string[];
  grant_types_supported?: string[];
  subject_types_supported?: string[];
  id_token_signing_alg_values_supported: string[];
  token_endpoint_auth_methods_supported?: string[];
  revocation_endpoint?: string;
  introspection_endpoint?: string;
  end_session_endpoint?: string;
}

export interface JWKSDocument {
  keys: jose.JWK[];
}

export interface OAuth2Error {
  error: string;
  error_description?: string;
  error_uri?: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
}

export interface IntrospectionResponse {
  active: boolean;
  scope?: string;
  client_id?: string;
  username?: string;
  token_type?: string;
  exp?: number;
  iat?: number;
  nbf?: number;
  sub?: string;
  aud?: string | string[];
  iss?: string;
  jti?: string;
}

// =============================================================================
// HTTP Client
// =============================================================================

/**
 * HTTP client wrapper with consistent error handling and response parsing.
 */
export const httpClient = {
  /**
   * Perform a GET request.
   */
  async get<T = unknown>(
    path: string,
    options: {
      headers?: Record<string, string>;
      followRedirects?: boolean;
    } = {}
  ): Promise<HttpResponse<T>> {
    const url = path.startsWith('http') ? path : `${API_BASE_URL}${path}`;
    const response = await fetch(url, {
      method: 'GET',
      headers: options.headers,
      redirect: options.followRedirects === false ? 'manual' : 'follow',
    });
    return parseResponse<T>(response);
  },

  /**
   * Perform a POST request with JSON body.
   */
  async postJson<T = unknown>(
    path: string,
    body: unknown,
    options: { headers?: Record<string, string> } = {}
  ): Promise<HttpResponse<T>> {
    const url = path.startsWith('http') ? path : `${API_BASE_URL}${path}`;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      body: JSON.stringify(body),
    });
    return parseResponse<T>(response);
  },

  /**
   * Perform a POST request with form-urlencoded body.
   * Standard format for OAuth token requests.
   */
  async postForm<T = unknown>(
    path: string,
    params: Record<string, string>,
    options: { headers?: Record<string, string> } = {}
  ): Promise<HttpResponse<T>> {
    const url = path.startsWith('http') ? path : `${API_BASE_URL}${path}`;
    const body = new URLSearchParams(params).toString();
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...options.headers,
      },
      body,
    });
    return parseResponse<T>(response);
  },

  /**
   * Perform a PUT request with JSON body.
   */
  async put<T = unknown>(
    path: string,
    body: unknown,
    options: { headers?: Record<string, string> } = {}
  ): Promise<HttpResponse<T>> {
    const url = path.startsWith('http') ? path : `${API_BASE_URL}${path}`;
    const response = await fetch(url, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      body: JSON.stringify(body),
    });
    return parseResponse<T>(response);
  },

  /**
   * Perform a DELETE request.
   */
  async delete<T = unknown>(
    path: string,
    options: { headers?: Record<string, string> } = {}
  ): Promise<HttpResponse<T>> {
    const url = path.startsWith('http') ? path : `${API_BASE_URL}${path}`;
    const response = await fetch(url, {
      method: 'DELETE',
      headers: options.headers,
    });
    return parseResponse<T>(response);
  },

  /**
   * Perform an OPTIONS request (for CORS testing).
   */
  async options(
    path: string,
    options: { headers?: Record<string, string> } = {}
  ): Promise<HttpResponse<null>> {
    const url = path.startsWith('http') ? path : `${API_BASE_URL}${path}`;
    const response = await fetch(url, {
      method: 'OPTIONS',
      headers: options.headers,
    });
    return {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
      data: null,
      raw: response,
    };
  },

  /**
   * Perform a POST request with raw body (for payload size testing).
   */
  async postRaw(
    path: string,
    body: string | Buffer,
    options: { headers?: Record<string, string> } = {}
  ): Promise<HttpResponse<unknown>> {
    const url = path.startsWith('http') ? path : `${API_BASE_URL}${path}`;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      body,
    });
    return parseResponse(response);
  },
};

/**
 * Parse response body based on content type.
 */
async function parseResponse<T>(response: Response): Promise<HttpResponse<T>> {
  const contentType = response.headers.get('content-type') || '';
  let data: T;

  if (contentType.includes('application/json')) {
    data = (await response.json()) as T;
  } else if (contentType.includes('text/') || contentType.includes('xml')) {
    data = (await response.text()) as T;
  } else {
    // For empty responses or unknown content types
    const text = await response.text();
    data = (text ? JSON.parse(text) : null) as T;
  }

  return {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
    data,
    raw: response,
  };
}

// =============================================================================
// OAuth-Specific Helpers
// =============================================================================

/**
 * Build Basic Auth header from client credentials.
 */
export function buildBasicAuth(clientId: string, clientSecret: string): string {
  const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
  return `Basic ${credentials}`;
}

/**
 * Build authorization URL with query parameters.
 */
export function buildAuthorizationUrl(params: {
  clientId: string;
  redirectUri: string;
  responseType?: string;
  scope?: string;
  state?: string;
  nonce?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  prompt?: string;
  maxAge?: number;
  responseMode?: string;
}): string {
  const searchParams = new URLSearchParams();
  searchParams.set('client_id', params.clientId);
  searchParams.set('redirect_uri', params.redirectUri);
  searchParams.set('response_type', params.responseType || 'code');

  if (params.scope) searchParams.set('scope', params.scope);
  if (params.state) searchParams.set('state', params.state);
  if (params.nonce) searchParams.set('nonce', params.nonce);
  if (params.codeChallenge) searchParams.set('code_challenge', params.codeChallenge);
  if (params.codeChallengeMethod) searchParams.set('code_challenge_method', params.codeChallengeMethod);
  if (params.prompt) searchParams.set('prompt', params.prompt);
  if (params.maxAge !== undefined) searchParams.set('max_age', params.maxAge.toString());
  if (params.responseMode) searchParams.set('response_mode', params.responseMode);

  return `${API_BASE_URL}/authorize?${searchParams.toString()}`;
}

// =============================================================================
// JWT Assertions
// =============================================================================

/**
 * Assert that a string is a valid JWT with expected structure.
 */
export function assertValidJWT(token: string, options: { checkSignature?: boolean } = {}): void {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error(`Invalid JWT structure: expected 3 parts, got ${parts.length}`);
  }

  // Decode header
  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
  if (!header.alg) {
    throw new Error('JWT header missing "alg" claim');
  }
  if (!header.typ && header.typ !== 'JWT') {
    // typ is optional but if present should be JWT
  }

  // Decode payload
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  if (!payload.iss) {
    throw new Error('JWT payload missing "iss" claim');
  }
  if (!payload.sub) {
    throw new Error('JWT payload missing "sub" claim');
  }
  if (!payload.exp) {
    throw new Error('JWT payload missing "exp" claim');
  }
}

/**
 * Decode a JWT without verification (for inspection).
 */
export function decodeJWT(token: string): { header: jose.JWTHeaderParameters; payload: jose.JWTPayload } {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error(`Invalid JWT structure: expected 3 parts, got ${parts.length}`);
  }

  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString()) as jose.JWTHeaderParameters;
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString()) as jose.JWTPayload;

  return { header, payload };
}

/**
 * Verify a JWT signature using JWKS.
 */
export async function verifyJWT(
  token: string,
  jwksUri: string
): Promise<{ header: jose.JWTHeaderParameters; payload: jose.JWTPayload }> {
  const JWKS = jose.createRemoteJWKSet(new URL(jwksUri));
  const { payload, protectedHeader } = await jose.jwtVerify(token, JWKS);
  return { header: protectedHeader, payload };
}

// =============================================================================
// OAuth Error Assertions
// =============================================================================

/**
 * Assert that a response contains a valid OAuth 2.0 error.
 */
export function assertOAuth2Error(
  response: HttpResponse<unknown>,
  expectedError: string,
  options: { expectedStatus?: number } = {}
): void {
  const { expectedStatus = 400 } = options;

  if (response.status !== expectedStatus) {
    throw new Error(
      `Expected status ${expectedStatus}, got ${response.status}. Body: ${JSON.stringify(response.data)}`
    );
  }

  const data = response.data as OAuth2Error;
  if (!data.error) {
    throw new Error(`Response missing "error" field. Body: ${JSON.stringify(response.data)}`);
  }

  if (data.error !== expectedError) {
    throw new Error(
      `Expected error "${expectedError}", got "${data.error}". Description: ${data.error_description}`
    );
  }
}

/**
 * Assert that a response is a successful token response.
 */
export function assertTokenResponse(response: HttpResponse<unknown>): TokenResponse {
  if (response.status !== 200) {
    throw new Error(`Expected status 200, got ${response.status}. Body: ${JSON.stringify(response.data)}`);
  }

  const data = response.data as TokenResponse;

  if (!data.access_token) {
    throw new Error('Token response missing "access_token"');
  }
  if (!data.token_type) {
    throw new Error('Token response missing "token_type"');
  }
  if (typeof data.expires_in !== 'number') {
    throw new Error('Token response missing or invalid "expires_in"');
  }

  return data;
}

// =============================================================================
// Header Assertions
// =============================================================================

/**
 * Assert that a response has a specific header with expected value.
 */
export function assertHeader(
  response: HttpResponse<unknown>,
  headerName: string,
  expectedValue?: string | RegExp
): void {
  const value = response.headers.get(headerName);

  if (value === null) {
    throw new Error(`Expected header "${headerName}" to be present, but it was not found`);
  }

  if (expectedValue !== undefined) {
    if (expectedValue instanceof RegExp) {
      if (!expectedValue.test(value)) {
        throw new Error(
          `Header "${headerName}" value "${value}" does not match pattern ${expectedValue}`
        );
      }
    } else if (value !== expectedValue) {
      throw new Error(`Header "${headerName}" expected "${expectedValue}", got "${value}"`);
    }
  }
}

/**
 * Assert that a response does NOT have a specific header value.
 */
export function assertHeaderNot(
  response: HttpResponse<unknown>,
  headerName: string,
  forbiddenValue: string
): void {
  const value = response.headers.get(headerName);

  if (value === forbiddenValue) {
    throw new Error(`Header "${headerName}" should not be "${forbiddenValue}"`);
  }
}

// =============================================================================
// Redirect Assertions
// =============================================================================

/**
 * Parse redirect location and extract query/fragment parameters.
 */
export function parseRedirectLocation(
  response: HttpResponse<unknown>
): { url: URL; params: URLSearchParams } | null {
  const location = response.headers.get('location');
  if (!location) return null;

  const url = new URL(location, API_BASE_URL);
  const params = new URLSearchParams(url.search || url.hash.slice(1));

  return { url, params };
}

/**
 * Assert that a response is a redirect to a specific location pattern.
 */
export function assertRedirect(
  response: HttpResponse<unknown>,
  expectedStatus: 301 | 302 | 303 | 307 | 308 = 303
): URL {
  if (response.status !== expectedStatus) {
    throw new Error(`Expected redirect status ${expectedStatus}, got ${response.status}`);
  }

  const location = response.headers.get('location');
  if (!location) {
    throw new Error('Redirect response missing Location header');
  }

  return new URL(location, API_BASE_URL);
}
