# ==============================================================================
# Password Authentication Strategy - Variables
# ==============================================================================

# ------------------------------------------------------------------------------
# Project & Environment
# ------------------------------------------------------------------------------

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "brand_name" {
  description = "Brand name displayed in login pages. Defaults to project_name if not set."
  type        = string
  default     = ""
}

# ------------------------------------------------------------------------------
# Required Dependencies (Injected from Infrastructure Modules)
# ------------------------------------------------------------------------------

variable "dynamodb_table_name" {
  description = "Name of the DynamoDB table (injected from dynamodb_core module)"
  type        = string
}

variable "dynamodb_table_arn" {
  description = "ARN of the DynamoDB table (for IAM policies)"
  type        = string
}

variable "dynamodb_encryption_key_arn" {
  description = "ARN of the KMS key used for DynamoDB encryption. Required for Lambda to decrypt data."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:kms:", var.dynamodb_encryption_key_arn))
    error_message = "Must be a valid KMS key ARN."
  }
}

variable "api_gateway_id" {
  description = "API Gateway HTTP API ID for route attachment"
  type        = string
}

variable "api_gateway_execution_arn" {
  description = "API Gateway execution ARN for Lambda permissions"
  type        = string
}

# ------------------------------------------------------------------------------
# Strategy Configuration
# ------------------------------------------------------------------------------

variable "csrf_secret" {
  description = "Secret key for CSRF token generation. Generate with: openssl rand -hex 32"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.csrf_secret) >= 64
    error_message = "CSRF secret must be at least 64 hex characters (32 bytes). Generate with: openssl rand -hex 32"
  }
}

variable "protocol_callback_url" {
  description = "URL to redirect after successful authentication (e.g., /authorize/callback)"
  type        = string
  default     = "/authorize/callback"
}

variable "mfa_validate_url" {
  description = "URL to redirect for MFA validation when user has MFA enabled. Leave empty to skip MFA check."
  type        = string
  default     = ""
}

# ------------------------------------------------------------------------------
# Lambda Configuration
# ------------------------------------------------------------------------------

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 10
}

variable "lambda_memory_size" {
  description = "Lambda function memory size in MB"
  type        = number
  default     = 256
}

variable "log_retention_days" {
  description = "CloudWatch log retention period in days"
  type        = number
  default     = 365

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.log_retention_days)
    error_message = "Log retention must be a valid CloudWatch retention value."
  }
}

# ------------------------------------------------------------------------------
# Brute Force Protection Configuration
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
  default     = 900 # 15 minutes

  validation {
    condition     = var.lockout_duration_seconds >= 300 && var.lockout_duration_seconds <= 86400
    error_message = "Lockout duration must be between 300 seconds (5 minutes) and 86400 seconds (24 hours)."
  }
}


# ------------------------------------------------------------------------------
# Password Reset Configuration (Optional - requires SES)
# ------------------------------------------------------------------------------

variable "ses_sender_email" {
  description = "Verified SES sender email for password reset emails. Leave empty to disable password reset feature."
  type        = string
  default     = ""
}

variable "ses_sender_name" {
  description = "Display name for password reset emails. Defaults to brand_name or project_name."
  type        = string
  default     = ""
}

variable "ses_configuration_set" {
  description = "Optional SES configuration set for email tracking"
  type        = string
  default     = ""
}

variable "password_reset_template_name" {
  description = "Name of the SES template for password reset emails"
  type        = string
  default     = ""
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

variable "password_reset_page_url" {
  description = "URL of the password reset form page (where users enter new password)"
  type        = string
  default     = "/auth/password/reset-form"
}

# ------------------------------------------------------------------------------
# Password Policy Configuration
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
