# ==============================================================================
# OAuth Server - Development Environment Configuration
# ==============================================================================
# All settings are explicit. Generate csrf_secret with: openssl rand -hex 32
#
# IMPORTANT: This file is for DEVELOPMENT ONLY.
# For production, create environments/prod/ with secure settings.
# ==============================================================================

# ------------------------------------------------------------------------------
# Project
# ------------------------------------------------------------------------------
project_name = "oauth-server"
environment  = "dev"
aws_region   = "us-east-1"
domain_name  = ""

# ------------------------------------------------------------------------------
# Security
# ------------------------------------------------------------------------------
# DEVELOPMENT ONLY: This hardcoded secret is for local development convenience.
# Production deployments MUST use a unique secret generated with:
#   openssl rand -hex 32
csrf_secret          = "4279fc974e6499cee650add964481b934aeb27e91374baa44b98fdb2c10cb868"
cors_allowed_origins = ["http://localhost:3000"]

# CORS Credentials: FALSE is correct for OAuth 2.1 public clients (SPAs with PKCE).
# Public clients authenticate via code_verifier, not cookies.
# Only set TRUE for Backend-For-Frontend (BFF) patterns with cookie sessions.
# Reference: IETF draft-ietf-oauth-browser-based-apps-22
cors_allow_credentials = false
cors_max_age           = 86400

# ------------------------------------------------------------------------------
# Client Registration Security (RFC 7591)
# Controls who can register new OAuth clients via POST /connect/register
# ------------------------------------------------------------------------------
# DEVELOPMENT: Allow open registration for testing
# PRODUCTION: Set client_registration_token and disable open registration
client_registration_token      = ""
allow_open_client_registration = true

# ------------------------------------------------------------------------------
# DynamoDB
# DEVELOPMENT: Disabled for easy cleanup
# PRODUCTION: Set both to true for data protection and SOC2 compliance
# ------------------------------------------------------------------------------
enable_deletion_protection    = false
enable_point_in_time_recovery = false

# ------------------------------------------------------------------------------
# KMS
# DEVELOPMENT: 7 days for faster cleanup
# PRODUCTION: Use 30 days to allow recovery from accidental deletion
# ------------------------------------------------------------------------------
kms_key_deletion_window_days = 7

# JWT Key ID (kid) - Identifier embedded in JWT headers and JWKS endpoint.
#
# PURPOSE:
# - Included in every signed JWT's header as the "kid" claim
# - Clients fetch JWKS and match "kid" to find the correct public key for verification
# - Enables key rotation without immediately invalidating existing tokens
#
# GRACEFUL KEY ROTATION (normal operations):
# 1. Create new KMS key, set new jwt_key_id (e.g., "jwt-key-2")
# 2. JWKS endpoint serves BOTH old and new public keys
# 3. New tokens signed with new key, old tokens still verify with old key
# 4. Wait for old tokens to expire (access_token TTL + refresh_token TTL)
# 5. Remove old public key from JWKS, schedule old KMS key for deletion
#
# IMMEDIATE KEY REVOCATION (security incidents):
# Change jwt_key_id WITHOUT serving old key in JWKS to instantly invalidate
# all existing tokens. Use when:
# - Private key compromised or suspected breach
# - Need to force logout all users immediately
# - Compliance requires immediate session termination
#
# NOTE: AWS does NOT auto-rotate asymmetric keys. Rotation is always manual.
jwt_key_id = "jwt-key-1"

# ------------------------------------------------------------------------------
# Logging
# DEVELOPMENT: 30 days for cost savings
# PRODUCTION: SOC2 requires minimum 365 days for audit trails
# ------------------------------------------------------------------------------
log_retention_days = 30

# ------------------------------------------------------------------------------
# API Gateway Throttling
# Protects against DDoS attacks and ensures fair usage across clients.
# ------------------------------------------------------------------------------
throttling_burst_limit = 1000
throttling_rate_limit  = 500

# ------------------------------------------------------------------------------
# Features
# Enable only the authentication strategies you need
# ------------------------------------------------------------------------------
enable_password_strategy = true
enable_saml_strategy     = true
enable_mfa_totp_strategy = false

# ------------------------------------------------------------------------------
# Token Lifetimes (seconds)
# ------------------------------------------------------------------------------
access_token_ttl  = 3600    # 1 hour
id_token_ttl      = 3600    # 1 hour
refresh_token_ttl = 2592000 # 30 days
