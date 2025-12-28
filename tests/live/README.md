# Live Integration Tests

End-to-end integration tests for the OAuth 2.1 / OpenID Connect Identity Provider.

## Prerequisites

- Node.js 20+
- AWS credentials configured (for DynamoDB verification tests)
- Network access to the deployed API Gateway

## Setup

```bash
cd tests/live
npm install
```

This automatically installs Playwright and downloads Chromium for browser tests.

## Configuration

Edit `config.json` to point to your deployment:

```json
{
  "apiBaseUrl": "https://your-api-gateway.execute-api.region.amazonaws.com",
  "dynamodbTable": "your-dynamodb-table",
  "awsRegion": "us-east-1"
}
```

Test fixtures are in `fixtures.json`. Ensure the test clients and users exist in your deployment.

## Running Tests

```bash
# Run API tests (fast, no browser)
npm test

# Run browser tests (requires Chromium)
npm run test:browser

# Run browser tests with visible browser
npm run test:browser:headed

# Run browser tests in debug mode
npm run test:browser:debug

# Run all tests (API + browser)
npm run test:all
```

### Filtering Tests

```bash
# Run specific API test by ID
npm test -- INF-01

# Run API test category
npm test -- --testNamePattern="^INF-"
npm test -- --testNamePattern="^DCR-"
npm test -- --testNamePattern="^AUT-"
npm test -- --testNamePattern="^TOK-"

# Run specific browser test
npm run test:browser -- --grep "TOK-01"
```

## Test Structure

```
tests/live/
├── specs/           # API tests (Vitest)
│   ├── INF-*.spec.ts
│   ├── DCR-*.spec.ts
│   └── ...
├── browser/         # Browser tests (Playwright)
│   ├── TOK-01-auth-code-flow.spec.ts
│   └── ...
├── helpers.ts       # API test utilities
├── browser/helpers.ts  # Browser test utilities
└── fixtures.json    # Test data
```

## Test Categories

| Category | Prefix | Type | Description |
|----------|--------|------|-------------|
| Infrastructure | INF-* | API | Discovery, JWKS, security headers |
| Dynamic Client Registration | DCR-* | API | RFC 7591 client registration |
| Authorization | AUT-* | API | Authorization endpoint validation |
| Token | TOK-* | Both | Token endpoint, grants, PKCE |
| Session | SES-* | Browser | Login UI, CSRF, MFA |
| User Management | USR-* | Both | SCIM provisioning, RBAC |
| Token Management | MGT-* | Both | Introspection, revocation |
| Logout | LOG-* | Browser | RP-initiated logout |
| SAML | SAM-* | API | SAML integration |
| JWT | JWT-* | API | Token structure and crypto |

## Skipped Tests

Some tests are skipped due to infrastructure limitations. See [SKIPPED.md](./SKIPPED.md) for details.

## Writing Tests

### API Tests (specs/)

```typescript
import { describe, it, expect } from 'vitest';
import { httpClient } from '../helpers';
import { ENDPOINTS } from '../setup';

describe('TEST-ID: Test Name', () => {
  it('should do something', async () => {
    const response = await httpClient.get(ENDPOINTS.discovery);
    expect(response.status).toBe(200);
  });
});
```

### Browser Tests (browser/)

```typescript
import { test, expect } from '@playwright/test';
import { login, TEST_USERS } from './helpers';

test.describe('TEST-ID: Test Name', () => {
  test('should do something', async ({ page }) => {
    await page.goto('/auth/login');
    await login(page, TEST_USERS.standard.email, TEST_USERS.standard.password);
    await expect(page).toHaveURL(/callback/);
  });
});
```

## Helpers

### API Helpers
- `httpClient` - HTTP client with consistent error handling
- `buildBasicAuth()` - Create Basic auth header
- `assertOAuth2Error()` - Validate OAuth error responses
- `assertTokenResponse()` - Validate token responses

### Browser Helpers
- `login(page, email, password)` - Fill and submit login form
- `generatePKCE()` - Generate PKCE challenge/verifier
- `buildAuthorizationUrl()` - Build /authorize URL with params
- `exchangeCodeForTokens()` - Exchange auth code for tokens
