# ==============================================================================
# Networking Module - Variables
# ==============================================================================
# Configuration for the API Gateway HTTP API.
# All values are injected from the environment's terraform.tfvars.
#
# OAUTH 2.1 COMPLIANCE (draft-ietf-oauth-v2-1-14):
# - Section 1.5: CORS origins must be explicit HTTPS URLs (localhost exempt for dev)
# - Section 7.7: Throttling protects against resource exhaustion attacks
# - SOC2: Logging enables audit trails for compliance
#
# DESIGN PRINCIPLE: No defaults for configurable settings.
# All values must be explicitly set in terraform.tfvars.
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

variable "cors_allowed_origins" {
  description = "List of allowed CORS origins. Must be explicit URLs, wildcards are blocked for security. Example: [\"https://app.example.com\"]"
  type        = list(string)

  validation {
    condition     = length(var.cors_allowed_origins) > 0
    error_message = "At least one CORS origin must be specified."
  }

  validation {
    condition     = !contains(var.cors_allowed_origins, "*")
    error_message = "Wildcard (*) CORS origin is not allowed for security reasons. Specify explicit origins."
  }

  validation {
    condition     = alltrue([for origin in var.cors_allowed_origins : !can(regex("^\\*\\.", origin))])
    error_message = "Wildcard subdomain patterns (*.example.com) are not allowed. Specify explicit origins."
  }

  validation {
    condition = alltrue([
      for origin in var.cors_allowed_origins :
      can(regex("^https://", origin)) || can(regex("^http://localhost(:[0-9]+)?$", origin))
    ])
    error_message = "CORS origins must use HTTPS, except http://localhost for development. OAuth 2.1 Section 1.5 requires HTTPS for production."
  }
}

variable "throttling_burst_limit" {
  description = "API Gateway throttling burst limit (maximum concurrent requests). Protects against DDoS and ensures fair usage."
  type        = number

  validation {
    condition     = var.throttling_burst_limit >= 100 && var.throttling_burst_limit <= 10000
    error_message = "Throttling burst limit must be between 100 and 10000."
  }
}

variable "throttling_rate_limit" {
  description = "API Gateway throttling rate limit (requests per second). Protects against DDoS and ensures fair usage."
  type        = number

  validation {
    condition     = var.throttling_rate_limit >= 100 && var.throttling_rate_limit <= 10000
    error_message = "Throttling rate limit must be between 100 and 10000."
  }
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days for API Gateway access logs. SOC2 compliance requires minimum 365 days for production audit trails."
  type        = number

  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653
    ], var.log_retention_days)
    error_message = "Log retention must be a valid CloudWatch retention period."
  }
}

variable "cors_allow_credentials" {
  description = "Access-Control-Allow-Credentials header. FALSE is correct for OAuth 2.1 public clients (SPAs with PKCE authenticate via code_verifier, not cookies). Only set TRUE for BFF patterns. Ref: IETF draft-ietf-oauth-browser-based-apps-22"
  type        = bool
}

variable "cors_max_age" {
  description = "CORS preflight cache duration in seconds (Access-Control-Max-Age). 86400 (24 hours) is the browser maximum."
  type        = number

  validation {
    condition     = var.cors_max_age >= 0 && var.cors_max_age <= 86400
    error_message = "CORS max age must be between 0 and 86400 seconds."
  }
}
