# ==============================================================================
# OAuth 2.1 Token Endpoint - Variables
# ==============================================================================
# This module follows the Dependency Injection pattern.
# Infrastructure dependencies (DynamoDB, KMS) are passed in as variables,
# keeping the protocol layer decoupled from infrastructure details.
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

# ------------------------------------------------------------------------------
# Required Dependencies (Injected from Infrastructure Modules)
# ------------------------------------------------------------------------------

variable "dynamodb_table_name" {
  description = "Name of the DynamoDB table (injected from dynamodb_core module)"
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
  description = "KMS Key ID for JWT signing (injected from kms_keyring module)"
  type        = string

  validation {
    condition     = length(var.kms_key_id) > 0
    error_message = "KMS Key ID is required for token signing."
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

variable "key_id" {
  description = "Key ID (kid) for JWT header - must match JWKS endpoint"
  type        = string

  validation {
    condition     = length(var.key_id) > 0
    error_message = "Key ID is required for JWT header (kid claim)."
  }
}

# ------------------------------------------------------------------------------
# Networking Dependencies
# ------------------------------------------------------------------------------

variable "api_gateway_id" {
  description = "API Gateway HTTP API ID (injected from networking module)"
  type        = string
}

variable "api_gateway_execution_arn" {
  description = "API Gateway execution ARN (for Lambda permissions)"
  type        = string
}

# ------------------------------------------------------------------------------
# Lambda Configuration
# ------------------------------------------------------------------------------

variable "environment" {
  description = "Deployment environment"
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

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
  description = "CloudWatch log retention for Lambda logs (SOC2 requires 365+ for production)"
  type        = number
  default     = 365

  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653
    ], var.lambda_log_retention_days)
    error_message = "Log retention must be a valid CloudWatch retention period."
  }
}

# ------------------------------------------------------------------------------
# Token Configuration
# ------------------------------------------------------------------------------

variable "issuer" {
  description = "OAuth 2.1 issuer URL (iss claim). MUST be HTTPS in production per OAuth 2.1 Section 1.5."
  type        = string

  validation {
    condition     = can(regex("^https://", var.issuer))
    error_message = "Issuer must be a valid HTTPS URL (HTTP not allowed per OAuth 2.1 Section 1.5)."
  }
}

variable "default_access_token_ttl" {
  description = "Default access token TTL in seconds"
  type        = number
  default     = 3600 # 1 hour

  validation {
    condition     = var.default_access_token_ttl >= 60 && var.default_access_token_ttl <= 86400
    error_message = "Access token TTL must be between 60 seconds and 24 hours."
  }
}

variable "default_id_token_ttl" {
  description = "Default ID token TTL in seconds (typically matches access token)"
  type        = number
  default     = 3600 # 1 hour

  validation {
    condition     = var.default_id_token_ttl >= 60 && var.default_id_token_ttl <= 86400
    error_message = "ID token TTL must be between 60 seconds and 24 hours."
  }
}

variable "default_refresh_token_ttl" {
  description = "Default refresh token TTL in seconds"
  type        = number
  default     = 2592000 # 30 days

  validation {
    condition     = var.default_refresh_token_ttl >= 3600 && var.default_refresh_token_ttl <= 31536000
    error_message = "Refresh token TTL must be between 1 hour and 1 year."
  }
}

# ------------------------------------------------------------------------------
# CORS Configuration
# ------------------------------------------------------------------------------

variable "allowed_origins" {
  description = "Allowed CORS origins for browser-based clients. Supports exact matches and wildcard patterns (e.g., https://*.example.com). Empty list allows all origins (for development only)."
  type        = list(string)
  default     = []
}
