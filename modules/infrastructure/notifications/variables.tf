# ==============================================================================
# Notifications Infrastructure Module - Variables
# ==============================================================================
# AWS SES configuration for transactional emails (password reset, verification).
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
# SES Configuration
# ------------------------------------------------------------------------------

variable "ses_sender_email" {
  description = "Verified sender email address for SES. Must be verified in SES before use."
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.ses_sender_email))
    error_message = "Must be a valid email address format."
  }
}

variable "ses_sender_name" {
  description = "Display name for the sender (e.g., 'OAuth Server')"
  type        = string
  default     = ""
}

variable "ses_configuration_set" {
  description = "Optional SES configuration set name for tracking and reputation management"
  type        = string
  default     = ""
}

# ------------------------------------------------------------------------------
# Template Configuration
# ------------------------------------------------------------------------------

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

variable "brand_name" {
  description = "Brand name displayed in email templates. Defaults to project_name if not set."
  type        = string
  default     = ""
}

# ------------------------------------------------------------------------------
# Token Configuration
# ------------------------------------------------------------------------------

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
