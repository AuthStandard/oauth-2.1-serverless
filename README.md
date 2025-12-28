# OAuth 2.1 Serverless Identity Provider

> [!NOTE]
> This project is under active development. Unit test coverage is in progress.

An open-source, standards-compliant OAuth 2.1 and OpenID Connect implementation. Built for SOC 2 environments on AWS Lambda, API Gateway, and DynamoDB.

## Why This Exists

Most identity solutions are either expensive SaaS products or complex self-hosted systems requiring dedicated infrastructure. This project provides a third option: deploy your own standards-compliant identity provider with a single command.

## Standards Compliance

**OAuth 2.1** (draft)
- Authorization Code Flow with PKCE (mandatory S256)
- Client Credentials Flow
- Refresh Token with Rotation

**OpenID Connect Core 1.0**
- ID Tokens with standard claims
- UserInfo Endpoint
- Discovery Document
- JWKS Endpoint

**Additional RFCs**
- Token Introspection (RFC 7662)
- Token Revocation (RFC 7009)
- Dynamic Client Registration (RFC 7591)
- SCIM 2.0 User Provisioning (RFC 7643/7644)

## Security

- PKCE required on all authorization requests (S256 only, plain rejected)
- CSRF protection on login forms
- Strict redirect URI validation (exact match, no wildcards)
- Refresh token rotation on every use
- KMS-based JWT signing (asymmetric RS256)
- Configurable token lifetimes

## Enterprise Ready

Built with compliance and auditability in mind:

- **SOC 2 Type II compatible** - Point-in-time recovery, audit logging, encryption at rest
- **OAuth 2.1 compliant** - Implements latest security best practices (mandatory PKCE, no implicit flow)
- **OpenID Connect certified patterns** - Standard discovery, JWKS, and token formats
- **SCIM 2.0** - Automated user provisioning for enterprise identity sync
- **SAML 2.0** - Federate with existing enterprise IdPs
- **Audit trail** - CloudWatch logs with configurable retention (365+ days for compliance)
- **Infrastructure as Code** - Reproducible deployments, change tracking via Terraform

## Deployment

### Prerequisites

- AWS account with credentials configured
- Terraform >= 1.0
- Node.js >= 18
- An S3 bucket for Terraform state

### Setup

```bash
# 1. Clone
git clone https://github.com/AuthStandard/oauth-2.1-serverless.git
cd oauth-2.1-serverless

# 2. Configure environment
cd environments/dev
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars - generate csrf_secret with: openssl rand -hex 32

# 3. Configure backend (edit config.mk with your S3 bucket)
cd ../..
# Edit environments/dev/config.mk - set TF_STATE_BUCKET

# 4. Deploy
make init
make plan
make apply
```

### Key Configuration Options

| Setting | Description |
|---------|-------------|
| `csrf_secret` | Required. Generate with `openssl rand -hex 32` |
| `cors_allowed_origins` | Frontend URLs allowed to make requests |
| `enable_password_strategy` | Enable username/password login |
| `enable_saml_strategy` | Enable SAML 2.0 federation |
| `access_token_ttl` | Access token lifetime in seconds |
| `refresh_token_ttl` | Refresh token lifetime in seconds |

See `environments/dev/terraform.tfvars.example` for all options.

## Testing

### Setup

```bash
# 1. Configure test environment
cd tests/live
cp config.example.json config.json
# Edit config.json with your deployed API URL

# 2. Install dependencies
npm install

# 3. Seed test data
cd scripts && npm install && npm run seed && cd ..
```

### Run Tests

```bash
# API tests (no browser needed)
npm test

# Browser tests (requires Playwright)
npm run test:browser

# Interactive test app
cd ../webapp && npx serve
```

## Customization

### Login Templates

Templates are in `templates/`. Edit the HTML and CSS to match your brand:
- `templates/login/` - Login page
- `templates/error/` - Error pages
- `templates/form-post/` - OAuth form_post response mode

### Adding Auth Strategies

Enable/disable authentication strategies in `terraform.tfvars`:
- `enable_password_strategy` - Username/password
- `enable_saml_strategy` - SAML 2.0 SSO
- `enable_mfa_totp_strategy` - TOTP-based MFA

## Project Structure

```
├── config.mk               # Environment selector
├── Makefile                # Deployment commands
├── environments/           # Per-environment Terraform configs
│   └── dev/
│       ├── config.mk       # AWS region, state bucket
│       └── terraform.tfvars # Your configuration
├── modules/                # Lambda functions
│   ├── protocols/          # OAuth2, OIDC handlers
│   ├── user-mgmt/          # Login, SCIM, password
│   └── infra/              # Discovery, JWKS, routing
├── templates/              # Login page HTML/CSS
└── tests/
    ├── live/               # Integration tests
    └── webapp/             # Manual test application
```

## Contributing

Contributions welcome. Areas that need work:
- Unit test coverage
- Documentation
- Device Authorization Grant (RFC 8628)

## License

Apache 2.0 - See [LICENSE](./LICENSE)
