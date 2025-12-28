# ==============================================================================
# DynamoDB Core Module - Variables
# ==============================================================================
# Configuration for the Single Table Design DynamoDB table.
# All values are injected from the environment's terraform.tfvars.
#
# DESIGN PRINCIPLE: No defaults for security-critical settings.
# This forces explicit configuration per environment, preventing
# accidental deployment with insecure defaults.
# ==============================================================================

variable "project_name" {
  description = "Project name for resource naming (lowercase, hyphens only)"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.project_name))
    error_message = "Project name must contain only lowercase letters, numbers, and hyphens."
  }

  validation {
    condition     = length(var.project_name) >= 3 && length(var.project_name) <= 32
    error_message = "Project name must be between 3 and 32 characters."
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

variable "enable_point_in_time_recovery" {
  description = "Enable point-in-time recovery for data protection. Required for SOC2 compliance in production environments."
  type        = bool

  # No default - forces explicit decision per environment
}

variable "enable_deletion_protection" {
  description = "Enable deletion protection to prevent accidental table deletion. Strongly recommended for production environments."
  type        = bool

  # No default - forces explicit decision per environment
}

variable "kms_key_deletion_window_days" {
  description = "KMS key deletion window in days. Minimum 7, maximum 30. Use 30 for production to allow recovery from accidental deletion."
  type        = number

  validation {
    condition     = var.kms_key_deletion_window_days >= 7 && var.kms_key_deletion_window_days <= 30
    error_message = "Key deletion window must be between 7 and 30 days per AWS requirements."
  }
}
