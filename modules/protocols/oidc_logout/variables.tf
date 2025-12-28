# ==============================================================================
# OIDC RP-Initiated Logout Endpoint - Variables
# ==============================================================================
# Dependency Injection pattern: Infrastructure dependencies passed as variables.
# All configuration comes from Terraform - no hardcoded defaults in Lambda code.
#
# @see https://openid.net/specs/openid-connect-rpinitiated-1_0.html
# ==============================================================================

# ------------------------------------------------------------------------------
# Project & Environment
# ------------------------------------------------------------------------------

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string

  validation {
    condition     = length(var.project_name) > 0 && length(var.project_name) <= 32
    error_message = "Project name must be between 1 and 32 characters."
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

# ------------------------------------------------------------------------------
# Required Dependencies (Injected from Infrastructure Modules)
# ------------------------------------------------------------------------------

variable "dynamodb_table_name" {
  description = "Name of the DynamoDB table for session and client data"
  type        = string

  validation {
    condition     = length(var.dynamodb_table_name) > 0
    error_message = "DynamoDB table name is required."
  }
}

variable "dynamodb_table_arn" {
  description = "ARN of the DynamoDB table (for IAM policies)"
  type        = string

  validation {
    condition     = can(regex("^arn:aws:dynamodb:", var.dynamodb_table_arn))
    error_message = "Must be a valid DynamoDB table ARN."
  }
}

variable "dynamodb_encryption_key_arn" {
  description = "ARN of the KMS key used for DynamoDB encryption. Required for Lambda to decrypt data."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:kms:", var.dynamodb_encryption_key_arn))
    error_message = "Must be a valid KMS key ARN."
  }
}

variable "kms_key_id" {
  description = "KMS Key ID for JWT signature verification"
  type        = string

  validation {
    condition     = length(var.kms_key_id) > 0
    error_message = "KMS Key ID is required for token verification."
  }
}

variable "kms_key_arn" {
  description = "KMS Key ARN (for IAM policies)"
  type        = string

  validation {
    condition     = can(regex("^arn:aws:kms:", var.kms_key_arn))
    error_message = "Must be a valid KMS key ARN."
  }
}

variable "issuer" {
  description = "OAuth 2.1 issuer URL for token validation. MUST be HTTPS in production."
  type        = string

  validation {
    condition     = can(regex("^https://", var.issuer))
    error_message = "Issuer must be a valid HTTPS URL."
  }
}

# ------------------------------------------------------------------------------
# Networking Dependencies
# ------------------------------------------------------------------------------

variable "api_gateway_id" {
  description = "API Gateway HTTP API ID"
  type        = string
}

variable "api_gateway_execution_arn" {
  description = "API Gateway execution ARN (for Lambda permissions)"
  type        = string
}

# ------------------------------------------------------------------------------
# Session Configuration
# ------------------------------------------------------------------------------

variable "session_cookie_name" {
  description = "Name of the session cookie to clear on logout. Must match the cookie name used by oauth2_authorize."
  type        = string
  default     = "__Host-sid"

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

variable "default_logout_redirect_url" {
  description = "Default URL to redirect to after logout when no valid post_logout_redirect_uri is provided. Leave empty to show confirmation page."
  type        = string
  default     = ""
}

# ------------------------------------------------------------------------------
# Lambda Configuration
# ------------------------------------------------------------------------------

variable "lambda_memory_size" {
  description = "Memory allocation for the Lambda function (MB)"
  type        = number
  default     = 256

  validation {
    condition     = var.lambda_memory_size >= 128 && var.lambda_memory_size <= 10240
    error_message = "Lambda memory must be between 128 MB and 10240 MB."
  }
}

variable "lambda_timeout" {
  description = "Lambda timeout in seconds"
  type        = number
  default     = 10

  validation {
    condition     = var.lambda_timeout >= 1 && var.lambda_timeout <= 900
    error_message = "Lambda timeout must be between 1 and 900 seconds."
  }
}

variable "lambda_log_retention_days" {
  description = "CloudWatch log retention for Lambda logs. SOC2 requires 365+ for production."
  type        = number
  default     = 365

  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653
    ], var.lambda_log_retention_days)
    error_message = "Log retention must be a valid CloudWatch retention period."
  }
}
