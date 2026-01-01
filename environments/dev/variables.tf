# ==============================================================================
# OAuth Server - Environment Variables
# ==============================================================================
# All configuration is explicit. No magic defaults based on environment name.
# ==============================================================================

variable "project_name" {
  description = "Project name for resource naming (lowercase, hyphens only)"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.project_name))
    error_message = "Project name must contain only lowercase letters, numbers, and hyphens."
  }
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]$", var.aws_region))
    error_message = "AWS region must be a valid region identifier (e.g., us-east-1)."
  }
}

variable "domain_name" {
  description = "Custom domain name for the IdP. Leave empty to use API Gateway URL."
  type        = string
  default     = ""
}

# ------------------------------------------------------------------------------
# Security Settings
# ------------------------------------------------------------------------------

variable "csrf_secret" {
  description = "Secret key for CSRF token generation. Generate with: openssl rand -hex 32"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.csrf_secret) >= 64
    error_message = "CSRF secret must be at least 64 hex characters (32 bytes). Generate with: openssl rand -hex 32"
  }

  validation {
    condition     = !can(regex("^0+$", var.csrf_secret))
    error_message = "CSRF secret cannot be all zeros. Generate a secure secret with: openssl rand -hex 32"
  }
}

variable "cors_allowed_origins" {
  description = "List of allowed CORS origins. Use specific origins in production."
  type        = list(string)

  validation {
    condition     = length(var.cors_allowed_origins) > 0
    error_message = "At least one CORS origin must be specified."
  }
}

variable "cors_allow_credentials" {
  description = "Access-Control-Allow-Credentials header. FALSE is correct for OAuth 2.1 public clients (SPAs with PKCE authenticate via code_verifier, not cookies). Only set TRUE for BFF patterns. Ref: IETF draft-ietf-oauth-browser-based-apps-22"
  type        = bool
  default     = false
}

variable "cors_max_age" {
  description = "CORS preflight cache duration in seconds (Access-Control-Max-Age). 86400 (24 hours) is the browser maximum."
  type        = number
  default     = 86400

  validation {
    condition     = var.cors_max_age >= 0 && var.cors_max_age <= 86400
    error_message = "CORS max age must be between 0 and 86400 seconds."
  }
}

# ------------------------------------------------------------------------------
# Client Registration Security (RFC 7591)
# ------------------------------------------------------------------------------

variable "client_registration_token" {
  description = "Initial Access Token for protecting client registration endpoint (RFC 7591 Section 1.2). If set, POST /connect/register requires this token. Generate with: openssl rand -base64 32"
  type        = string
  default     = ""
  sensitive   = true
}

variable "allow_open_client_registration" {
  description = "Allow client registration without Initial Access Token. Set to false in production unless client_registration_token is configured."
  type        = bool
  default     = false
}

# ==============================================================================
# Production Environment Validation
# ==============================================================================
# These validations ensure production deployments use secure settings.
# They are implemented as local values with preconditions to provide
# clear error messages when production requirements are not met.
# ==============================================================================

locals {
  # Production security validations
  _validate_prod_deletion_protection = (
    var.environment != "prod" || var.enable_deletion_protection == true
  )
  _validate_prod_pitr = (
    var.environment != "prod" || var.enable_point_in_time_recovery == true
  )
  _validate_prod_log_retention = (
    var.environment != "prod" || var.log_retention_days >= 365
  )
  _validate_prod_kms_deletion = (
    var.environment != "prod" || var.kms_key_deletion_window_days >= 30
  )
  _validate_prod_open_registration = (
    var.environment != "prod" || var.allow_open_client_registration == false
  )
}

# Production validation checks (will fail during plan if conditions not met)
resource "null_resource" "production_validations" {
  count = var.environment == "prod" ? 1 : 0

  lifecycle {
    precondition {
      condition     = var.enable_deletion_protection == true
      error_message = "PRODUCTION REQUIREMENT: enable_deletion_protection must be true for production deployments."
    }
    precondition {
      condition     = var.enable_point_in_time_recovery == true
      error_message = "PRODUCTION REQUIREMENT: enable_point_in_time_recovery must be true for SOC2 compliance."
    }
    precondition {
      condition     = var.log_retention_days >= 365
      error_message = "PRODUCTION REQUIREMENT: log_retention_days must be at least 365 for SOC2 compliance."
    }
    precondition {
      condition     = var.kms_key_deletion_window_days >= 30
      error_message = "PRODUCTION REQUIREMENT: kms_key_deletion_window_days must be 30 for production."
    }
    precondition {
      condition     = var.allow_open_client_registration == false
      error_message = "PRODUCTION REQUIREMENT: allow_open_client_registration must be false. Use client_registration_token instead."
    }
  }
}

# ------------------------------------------------------------------------------
# DynamoDB Settings
# ------------------------------------------------------------------------------

variable "enable_deletion_protection" {
  description = "Enable DynamoDB deletion protection. Required for production."
  type        = bool
}

variable "enable_point_in_time_recovery" {
  description = "Enable DynamoDB point-in-time recovery. Required for SOC2 compliance."
  type        = bool
}

# ------------------------------------------------------------------------------
# KMS Settings
# ------------------------------------------------------------------------------

variable "kms_key_deletion_window_days" {
  description = "KMS key deletion window in days. Use 30 for production."
  type        = number

  validation {
    condition     = var.kms_key_deletion_window_days >= 7 && var.kms_key_deletion_window_days <= 30
    error_message = "KMS key deletion window must be between 7 and 30 days."
  }
}

variable "jwt_key_id" {
  description = "JWT Key ID (kid) for the JWT header. Used for key selection during rotation. Increment when rotating keys (e.g., jwt-key-1 -> jwt-key-2)."
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9_-]+$", var.jwt_key_id))
    error_message = "JWT Key ID must contain only alphanumeric characters, hyphens, and underscores."
  }

  validation {
    condition     = length(var.jwt_key_id) >= 1 && length(var.jwt_key_id) <= 64
    error_message = "JWT Key ID must be between 1 and 64 characters."
  }
}

# ------------------------------------------------------------------------------
# Logging Settings
# ------------------------------------------------------------------------------

variable "log_retention_days" {
  description = "CloudWatch log retention in days. SOC2 requires 365+ for production."
  type        = number

  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653
    ], var.log_retention_days)
    error_message = "Log retention must be a valid CloudWatch retention period."
  }
}

# ------------------------------------------------------------------------------
# API Gateway Throttling
# ------------------------------------------------------------------------------

variable "throttling_burst_limit" {
  description = "API Gateway throttling burst limit (maximum concurrent requests). Protects against DDoS."
  type        = number
  default     = 1000

  validation {
    condition     = var.throttling_burst_limit >= 100 && var.throttling_burst_limit <= 10000
    error_message = "Throttling burst limit must be between 100 and 10000."
  }
}

variable "throttling_rate_limit" {
  description = "API Gateway throttling rate limit (requests per second). Protects against DDoS."
  type        = number
  default     = 500

  validation {
    condition     = var.throttling_rate_limit >= 100 && var.throttling_rate_limit <= 10000
    error_message = "Throttling rate limit must be between 100 and 10000."
  }
}

# ------------------------------------------------------------------------------
# Feature Flags
# ------------------------------------------------------------------------------

variable "enable_password_strategy" {
  description = "Enable password authentication strategy"
  type        = bool
}

variable "enable_saml_strategy" {
  description = "Enable SAML authentication strategy"
  type        = bool
}

variable "enable_mfa_totp_strategy" {
  description = "Enable TOTP MFA strategy"
  type        = bool
  default     = false
}

# ------------------------------------------------------------------------------
# Branding
# ------------------------------------------------------------------------------

variable "brand_name" {
  description = "Brand name displayed in login pages and emails. Defaults to project_name if not set."
  type        = string
  default     = ""
}

# ------------------------------------------------------------------------------
# SES / Email Configuration (Optional)
# ------------------------------------------------------------------------------

variable "ses_sender_email" {
  description = "Verified SES sender email for transactional emails. Leave empty to disable email features."
  type        = string
  default     = ""
}

variable "ses_sender_name" {
  description = "Display name for transactional emails. Defaults to brand_name or project_name."
  type        = string
  default     = ""
}

variable "ses_configuration_set" {
  description = "Optional SES configuration set for email tracking"
  type        = string
  default     = ""
}

variable "password_reset_subject" {
  description = "Subject line for password reset emails"
  type        = string
  default     = "Reset Your Password"
}

variable "email_verification_subject" {
  description = "Subject line for email verification emails"
  type        = string
  default     = "Verify Your Email Address"
}

variable "password_reset_token_ttl" {
  description = "Password reset token TTL in seconds (default: 1 hour)"
  type        = number
  default     = 3600

  validation {
    condition     = var.password_reset_token_ttl >= 300 && var.password_reset_token_ttl <= 86400
    error_message = "Password reset token TTL must be between 5 minutes and 24 hours."
  }
}

variable "email_verification_token_ttl" {
  description = "Email verification token TTL in seconds (default: 24 hours)"
  type        = number
  default     = 86400

  validation {
    condition     = var.email_verification_token_ttl >= 3600 && var.email_verification_token_ttl <= 604800
    error_message = "Email verification token TTL must be between 1 hour and 7 days."
  }
}

variable "password_reset_page_url" {
  description = "URL of the password reset form page (where users enter new password)"
  type        = string
  default     = "/auth/password/reset-form"
}

# ------------------------------------------------------------------------------
# Password Policy
# ------------------------------------------------------------------------------

variable "password_min_length" {
  description = "Minimum password length"
  type        = number
  default     = 8

  validation {
    condition     = var.password_min_length >= 8 && var.password_min_length <= 128
    error_message = "Password minimum length must be between 8 and 128 characters."
  }
}

variable "password_require_uppercase" {
  description = "Require at least one uppercase letter"
  type        = bool
  default     = true
}

variable "password_require_lowercase" {
  description = "Require at least one lowercase letter"
  type        = bool
  default     = true
}

variable "password_require_number" {
  description = "Require at least one number"
  type        = bool
  default     = true
}

variable "password_require_special" {
  description = "Require at least one special character"
  type        = bool
  default     = false
}

# ------------------------------------------------------------------------------
# Brute Force Protection
# ------------------------------------------------------------------------------

variable "max_failed_login_attempts" {
  description = "Maximum failed login attempts before account lockout"
  type        = number
  default     = 5

  validation {
    condition     = var.max_failed_login_attempts >= 3 && var.max_failed_login_attempts <= 10
    error_message = "Max failed login attempts must be between 3 and 10."
  }
}

variable "lockout_duration_seconds" {
  description = "Account lockout duration in seconds after max failed attempts"
  type        = number
  default     = 900

  validation {
    condition     = var.lockout_duration_seconds >= 300 && var.lockout_duration_seconds <= 86400
    error_message = "Lockout duration must be between 300 seconds (5 minutes) and 86400 seconds (24 hours)."
  }
}

# ------------------------------------------------------------------------------
# TOTP MFA Configuration
# ------------------------------------------------------------------------------

variable "totp_issuer" {
  description = "Issuer name shown in authenticator apps. Defaults to brand_name or project_name."
  type        = string
  default     = ""
}

variable "totp_digits" {
  description = "Number of digits in TOTP code (6 or 8)"
  type        = number
  default     = 6

  validation {
    condition     = contains([6, 8], var.totp_digits)
    error_message = "TOTP digits must be 6 or 8."
  }
}

variable "totp_period" {
  description = "TOTP time step in seconds (default: 30)"
  type        = number
  default     = 30

  validation {
    condition     = var.totp_period >= 30 && var.totp_period <= 60
    error_message = "TOTP period must be between 30 and 60 seconds."
  }
}

variable "totp_window" {
  description = "Number of time steps to allow for clock drift (default: 1 = ±30 seconds)"
  type        = number
  default     = 1

  validation {
    condition     = var.totp_window >= 0 && var.totp_window <= 2
    error_message = "TOTP window must be between 0 and 2."
  }
}

variable "backup_codes_count" {
  description = "Number of backup codes to generate (default: 10)"
  type        = number
  default     = 10

  validation {
    condition     = var.backup_codes_count >= 5 && var.backup_codes_count <= 20
    error_message = "Backup codes count must be between 5 and 20."
  }
}

# ------------------------------------------------------------------------------
# Token Configuration
# ------------------------------------------------------------------------------

variable "access_token_ttl" {
  description = "Access token TTL in seconds (default: 1 hour)"
  type        = number
  default     = 3600

  validation {
    condition     = var.access_token_ttl >= 60 && var.access_token_ttl <= 86400
    error_message = "Access token TTL must be between 60 seconds and 24 hours."
  }
}

variable "id_token_ttl" {
  description = "ID token TTL in seconds (default: 1 hour, typically matches access token)"
  type        = number
  default     = 3600

  validation {
    condition     = var.id_token_ttl >= 60 && var.id_token_ttl <= 86400
    error_message = "ID token TTL must be between 60 seconds and 24 hours."
  }
}

variable "refresh_token_ttl" {
  description = "Refresh token TTL in seconds (default: 30 days)"
  type        = number
  default     = 2592000

  validation {
    condition     = var.refresh_token_ttl >= 3600 && var.refresh_token_ttl <= 31536000
    error_message = "Refresh token TTL must be between 1 hour and 1 year."
  }
}

# ------------------------------------------------------------------------------
# Session Configuration (OIDC Logout)
# ------------------------------------------------------------------------------

variable "session_cookie_name" {
  description = "Name of the session cookie to clear on logout"
  type        = string
  default     = "sid"

  validation {
    condition     = length(var.session_cookie_name) > 0 && length(var.session_cookie_name) <= 64
    error_message = "Session cookie name must be between 1 and 64 characters."
  }
}

variable "session_cookie_domain" {
  description = "Domain for the session cookie. Leave empty to use the current domain."
  type        = string
  default     = ""
}
