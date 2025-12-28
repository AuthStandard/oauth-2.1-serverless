# ==============================================================================
# KMS Keyring Module - Variables
# ==============================================================================
# Configuration for the asymmetric RSA key used for JWT signing (RS256).
# All values are injected from the environment's terraform.tfvars.
#
# IMPORTANT: The JWT 'kid' (Key ID) is NOT managed here. It is passed
# separately to protocol modules via terraform.tfvars to allow stable
# identifiers that persist across KMS key rotation.
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

variable "key_deletion_window_days" {
  description = "KMS key deletion window in days. Minimum 7, maximum 30. Use 30 for production to allow recovery from accidental deletion."
  type        = number

  validation {
    condition     = var.key_deletion_window_days >= 7 && var.key_deletion_window_days <= 30
    error_message = "Key deletion window must be between 7 and 30 days per AWS requirements."
  }
}
