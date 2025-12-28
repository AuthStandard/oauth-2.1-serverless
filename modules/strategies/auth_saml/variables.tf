# ==============================================================================
# SAML Authentication Strategy - Variables
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
  description = "API Gateway HTTP API ID (injected from networking module)"
  type        = string
}

variable "api_gateway_execution_arn" {
  description = "API Gateway execution ARN (for Lambda permissions)"
  type        = string
}

# ------------------------------------------------------------------------------
# SAML Configuration
# ------------------------------------------------------------------------------

variable "entity_id" {
  description = "SAML Service Provider Entity ID (must be globally unique URI)"
  type        = string
}

variable "assertion_consumer_service_url" {
  description = "Full URL for receiving SAML assertions (e.g., https://auth.example.com/auth/saml/callback)"
  type        = string
}

variable "issuer" {
  description = "OAuth 2.1 issuer URL for organization info in SP metadata"
  type        = string
}

variable "protocol_callback_url" {
  description = "URL to redirect after successful SAML authentication (e.g., /authorize/callback)"
  type        = string
  default     = "/authorize/callback"
}

# ------------------------------------------------------------------------------
# Lambda Configuration
# ------------------------------------------------------------------------------

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 10

  validation {
    condition     = var.lambda_timeout >= 3 && var.lambda_timeout <= 30
    error_message = "Lambda timeout must be between 3 and 30 seconds."
  }
}

variable "lambda_memory_size" {
  description = "Lambda function memory size in MB"
  type        = number
  default     = 256

  validation {
    condition     = var.lambda_memory_size >= 128 && var.lambda_memory_size <= 1024
    error_message = "Lambda memory must be between 128 and 1024 MB."
  }
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
