/**
 * Test Fixtures
 */

import * as crypto from 'crypto';
import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load generated fixtures from seed script
const fixturesPath = join(__dirname, 'fixtures.json');
const fixtures = existsSync(fixturesPath)
  ? JSON.parse(readFileSync(fixturesPath, 'utf-8'))
  : { clients: {}, users: {} };

export const TEST_CLIENTS = {
  confidential: fixtures.clients['test-app'] || { client_id: 'test-app', client_secret: '', redirect_uri: '' },
  public: fixtures.clients['test-public-app'] || { client_id: 'test-public-app', redirect_uri: '' },
  adminCli: fixtures.clients['admin-cli'] || { client_id: 'admin-cli', client_secret: '' },
};

export const TEST_USERS = {
  standard: fixtures.users['test-user-001'] || { email: '', password: '', sub: '' },
  admin: fixtures.users['test-user-002'] || { email: '', password: '', sub: '' },
};

// PKCE utilities
export function generateCodeVerifier(length = 64): string {
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  return Array.from(crypto.randomBytes(length)).map((b) => charset[b % charset.length]).join('');
}

export function generateCodeChallenge(verifier: string): string {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

export function generatePKCE(): { verifier: string; challenge: string } {
  const verifier = generateCodeVerifier();
  return { verifier, challenge: generateCodeChallenge(verifier) };
}

export function generateState(): string {
  return crypto.randomBytes(16).toString('hex');
}

export function generateNonce(): string {
  return crypto.randomBytes(16).toString('hex');
}

// DCR payloads
export function createValidDCRPayload(overrides: Record<string, unknown> = {}) {
  return {
    client_name: `Test Client ${Date.now()}`,
    redirect_uris: ['https://example.com/callback'],
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: 'client_secret_basic',
    ...overrides,
  };
}

export const MALICIOUS_VALUES = {
  xssScript: '<script>alert(1)</script>',
  sqlInjection: "' OR 1=1 --",
};

export const INVALID_CLIENT_IDS = {
  nonexistent: 'nonexistent-client-id-12345',
  malformed: 'not a valid uuid!',
};
