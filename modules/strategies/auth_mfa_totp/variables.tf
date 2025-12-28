# ==============================================================================
# TOTP MFA Strategy Module - Variables
# ==============================================================================
# Multi-Factor Authentication using Time-based One-Time Passwords (TOTP).
# Compatible with Google Authenticator, Authy, 1Password, etc.
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

variable "brand_name" {
  description = "Brand name displayed in authenticator apps. Defaults to project_name if not set."
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
  description = "ARN of the KMS key used for DynamoDB encryption"
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
# TOTP Configuration
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
