# ==============================================================================
# OIDC Discovery Endpoint - Variables
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

variable "api_gateway_id" {
  description = "API Gateway HTTP API ID (injected from networking module)"
  type        = string
}

variable "api_gateway_execution_arn" {
  description = "API Gateway execution ARN (for Lambda permissions)"
  type        = string
}

variable "issuer" {
  description = "OAuth 2.1 issuer URL (iss claim). MUST be HTTPS per OAuth 2.1 Section 1.5 and OIDC Discovery 1.0."
  type        = string

  validation {
    condition     = can(regex("^https://", var.issuer))
    error_message = "Issuer must be a valid HTTPS URL (HTTP not allowed per OAuth 2.1 Section 1.5)."
  }
}

variable "kms_key_id" {
  description = "KMS Key ID for JWT signing (used by JWKS endpoint)"
  type        = string
}

variable "kms_key_arn" {
  description = "KMS Key ARN for IAM policy"
  type        = string
}

variable "key_id" {
  description = "Key ID (kid) to use in JWKS response - must be unique and stable"
  type        = string

  validation {
    condition     = length(var.key_id) > 0
    error_message = "Key ID is required for JWKS endpoint."
  }
}

# ------------------------------------------------------------------------------
# Lambda Configuration
# ------------------------------------------------------------------------------

variable "lambda_memory_size" {
  description = "Memory allocation for the Lambda function (MB)"
  type        = number
  default     = 128

  validation {
    condition     = var.lambda_memory_size >= 128 && var.lambda_memory_size <= 10240
    error_message = "Lambda memory must be between 128 MB and 10240 MB."
  }
}

variable "lambda_timeout" {
  description = "Lambda timeout in seconds"
  type        = number
  default     = 5

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
