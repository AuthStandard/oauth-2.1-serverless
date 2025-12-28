# ==============================================================================
# OAuth 2.1 Authorization Endpoint - Variables
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
  description = "CloudWatch log retention in days. SOC2 requires 365+ for production."
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
# Authorization Flow Configuration
# ------------------------------------------------------------------------------

variable "login_router_url" {
  description = "URL of the login router endpoint (where users are redirected to authenticate). Can be a relative path (e.g., /login) or absolute URL."
  type        = string

  validation {
    condition     = length(var.login_router_url) > 0
    error_message = "Login router URL is required."
  }
}

variable "session_ttl_seconds" {
  description = "TTL for login sessions in seconds (default: 10 minutes)"
  type        = number
  default     = 600

  validation {
    condition     = var.session_ttl_seconds >= 60 && var.session_ttl_seconds <= 3600
    error_message = "Session TTL must be between 60 seconds (1 minute) and 3600 seconds (1 hour)."
  }
}

variable "code_ttl_seconds" {
  description = "TTL for authorization codes in seconds (default: 10 minutes). Per OAuth 2.1 security recommendations, should be short-lived."
  type        = number
  default     = 600

  validation {
    condition     = var.code_ttl_seconds >= 60 && var.code_ttl_seconds <= 600
    error_message = "Authorization code TTL must be between 60 seconds and 600 seconds (10 minutes) per OAuth 2.1 security recommendations."
  }
}

variable "issuer" {
  description = "OAuth 2.1 issuer URL (iss claim) for mix-up attack mitigation. REQUIRED per OAuth 2.1 Section 7.14. MUST be HTTPS in production."
  type        = string

  validation {
    condition     = can(regex("^https://", var.issuer))
    error_message = "Issuer must be a valid HTTPS URL (HTTP not allowed per OAuth 2.1 Section 1.5)."
  }
}

# ------------------------------------------------------------------------------
# Session Cookie Configuration (OIDC prompt=none support)
# ------------------------------------------------------------------------------

variable "session_cookie_name" {
  description = "Name of the session cookie for authenticated user sessions. Default uses __Host- prefix for enhanced security."
  type        = string
  default     = "__Host-sid"

  validation {
    condition     = length(var.session_cookie_name) > 0 && length(var.session_cookie_name) <= 64
    error_message = "Session cookie name must be between 1 and 64 characters."
  }
}

variable "session_cookie_domain" {
  description = "Domain for the session cookie. Leave empty for __Host- prefix cookies (recommended). Only set for cross-subdomain sessions."
  type        = string
  default     = ""
}

variable "auth_session_ttl_seconds" {
  description = "TTL for authenticated user sessions in seconds (default: 24 hours). Controls how long prompt=none silent auth works."
  type        = number
  default     = 86400

  validation {
    condition     = var.auth_session_ttl_seconds >= 300 && var.auth_session_ttl_seconds <= 604800
    error_message = "Auth session TTL must be between 300 seconds (5 minutes) and 604800 seconds (7 days)."
  }
}
