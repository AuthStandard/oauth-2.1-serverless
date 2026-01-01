# ==============================================================================
# OAuth Server - Main Entry Point
# ==============================================================================
# All configuration comes from terraform.tfvars - no magic conditionals.
# ==============================================================================

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# ==============================================================================
# Local Variables
# ==============================================================================

locals {
  issuer = var.domain_name != "" ? "https://${var.domain_name}" : module.networking.api_endpoint
}

# ==============================================================================
# Infrastructure Modules
# ==============================================================================

module "dynamodb_core" {
  source = "../../modules/infrastructure/dynamodb_core"

  project_name                  = var.project_name
  environment                   = var.environment
  enable_deletion_protection    = var.enable_deletion_protection
  enable_point_in_time_recovery = var.enable_point_in_time_recovery
  kms_key_deletion_window_days  = var.kms_key_deletion_window_days
}

module "kms_keyring" {
  source = "../../modules/infrastructure/kms_keyring"

  project_name             = var.project_name
  environment              = var.environment
  key_deletion_window_days = var.kms_key_deletion_window_days
}

module "networking" {
  source = "../../modules/infrastructure/networking"

  project_name           = var.project_name
  environment            = var.environment
  cors_allowed_origins   = var.cors_allowed_origins
  cors_allow_credentials = var.cors_allow_credentials
  cors_max_age           = var.cors_max_age
  log_retention_days     = var.log_retention_days
  throttling_burst_limit = var.throttling_burst_limit
  throttling_rate_limit  = var.throttling_rate_limit
}

# Note: Logging module deprecated - each Lambda module manages its own log groups

# ==============================================================================
# Notifications Module (Optional - for email features)
# ==============================================================================

module "notifications" {
  source = "../../modules/infrastructure/notifications"
  count  = var.ses_sender_email != "" ? 1 : 0

  project_name                 = var.project_name
  environment                  = var.environment
  ses_sender_email             = var.ses_sender_email
  ses_sender_name              = var.ses_sender_name
  ses_configuration_set        = var.ses_configuration_set
  brand_name                   = var.brand_name
  password_reset_subject       = var.password_reset_subject
  email_verification_subject   = var.email_verification_subject
  password_reset_token_ttl     = var.password_reset_token_ttl
  email_verification_token_ttl = var.email_verification_token_ttl
}

# ==============================================================================
# Protocol Modules
# ==============================================================================

module "oauth2_authorize" {
  source = "../../modules/protocols/oauth2_authorize"

  project_name                = var.project_name
  environment                 = var.environment
  dynamodb_table_name         = module.dynamodb_core.table_name
  dynamodb_table_arn          = module.dynamodb_core.table_arn
  dynamodb_encryption_key_arn = module.dynamodb_core.encryption_key_arn
  api_gateway_id              = module.networking.api_gateway_id
  api_gateway_execution_arn   = module.networking.api_gateway_execution_arn
  login_router_url            = "/auth/password/login"
  issuer                      = local.issuer
  lambda_log_retention_days   = var.log_retention_days
}

module "oauth2_token" {
  source = "../../modules/protocols/oauth2_token"

  project_name                = var.project_name
  environment                 = var.environment
  dynamodb_table_name         = module.dynamodb_core.table_name
  dynamodb_table_arn          = module.dynamodb_core.table_arn
  dynamodb_encryption_key_arn = module.dynamodb_core.encryption_key_arn
  kms_key_id                  = module.kms_keyring.key_id
  kms_key_arn                 = module.kms_keyring.key_arn
  key_id                      = var.jwt_key_id
  api_gateway_id              = module.networking.api_gateway_id
  api_gateway_execution_arn   = module.networking.api_gateway_execution_arn
  issuer                      = local.issuer
  lambda_log_retention_days   = var.log_retention_days
  default_access_token_ttl    = var.access_token_ttl
  default_id_token_ttl        = var.id_token_ttl
  default_refresh_token_ttl   = var.refresh_token_ttl
  allowed_origins             = var.cors_allowed_origins
}

module "oidc_discovery" {
  source = "../../modules/protocols/oidc_discovery"

  project_name              = var.project_name
  environment               = var.environment
  api_gateway_id            = module.networking.api_gateway_id
  api_gateway_execution_arn = module.networking.api_gateway_execution_arn
  issuer                    = local.issuer
  kms_key_id                = module.kms_keyring.key_id
  kms_key_arn               = module.kms_keyring.key_arn
  key_id                    = var.jwt_key_id
  lambda_log_retention_days = var.log_retention_days
}

module "oidc_userinfo" {
  source = "../../modules/protocols/oidc_userinfo"

  project_name                = var.project_name
  environment                 = var.environment
  dynamodb_table_name         = module.dynamodb_core.table_name
  dynamodb_table_arn          = module.dynamodb_core.table_arn
  dynamodb_encryption_key_arn = module.dynamodb_core.encryption_key_arn
  kms_key_id                  = module.kms_keyring.key_id
  kms_key_arn                 = module.kms_keyring.key_arn
  api_gateway_id              = module.networking.api_gateway_id
  api_gateway_execution_arn   = module.networking.api_gateway_execution_arn
  issuer                      = local.issuer
  lambda_log_retention_days   = var.log_retention_days
}

module "oauth2_revoke" {
  source = "../../modules/protocols/oauth2_revoke"

  project_name                = var.project_name
  environment                 = var.environment
  dynamodb_table_name         = module.dynamodb_core.table_name
  dynamodb_table_arn          = module.dynamodb_core.table_arn
  dynamodb_encryption_key_arn = module.dynamodb_core.encryption_key_arn
  api_gateway_id              = module.networking.api_gateway_id
  api_gateway_execution_arn   = module.networking.api_gateway_execution_arn
  lambda_log_retention_days   = var.log_retention_days
}

module "oauth2_introspect" {
  source = "../../modules/protocols/oauth2_introspect"

  project_name                = var.project_name
  environment                 = var.environment
  dynamodb_table_name         = module.dynamodb_core.table_name
  dynamodb_table_arn          = module.dynamodb_core.table_arn
  dynamodb_encryption_key_arn = module.dynamodb_core.encryption_key_arn
  kms_key_id                  = module.kms_keyring.key_id
  kms_key_arn                 = module.kms_keyring.key_arn
  api_gateway_id              = module.networking.api_gateway_id
  api_gateway_execution_arn   = module.networking.api_gateway_execution_arn
  issuer                      = local.issuer
  lambda_log_retention_days   = var.log_retention_days
}

module "oidc_logout" {
  source = "../../modules/protocols/oidc_logout"

  project_name                = var.project_name
  environment                 = var.environment
  dynamodb_table_name         = module.dynamodb_core.table_name
  dynamodb_table_arn          = module.dynamodb_core.table_arn
  dynamodb_encryption_key_arn = module.dynamodb_core.encryption_key_arn
  kms_key_id                  = module.kms_keyring.key_id
  kms_key_arn                 = module.kms_keyring.key_arn
  api_gateway_id              = module.networking.api_gateway_id
  api_gateway_execution_arn   = module.networking.api_gateway_execution_arn
  issuer                      = local.issuer
  lambda_log_retention_days   = var.log_retention_days
  session_cookie_name         = var.session_cookie_name
  session_cookie_domain       = var.session_cookie_domain
}

# ==============================================================================
# Strategy Modules
# ==============================================================================

module "auth_password" {
  source = "../../modules/strategies/auth_password"
  count  = var.enable_password_strategy ? 1 : 0

  project_name                = var.project_name
  environment                 = var.environment
  dynamodb_table_name         = module.dynamodb_core.table_name
  dynamodb_table_arn          = module.dynamodb_core.table_arn
  dynamodb_encryption_key_arn = module.dynamodb_core.encryption_key_arn
  api_gateway_id              = module.networking.api_gateway_id
  api_gateway_execution_arn   = module.networking.api_gateway_execution_arn
  csrf_secret                 = var.csrf_secret
  log_retention_days          = var.log_retention_days
  brand_name                  = var.brand_name

  # MFA integration (optional - requires auth_mfa_totp module)
  mfa_validate_url = var.enable_mfa_totp_strategy ? "/auth/mfa/validate-page" : ""

  # Password reset configuration (optional - requires SES)
  ses_sender_email             = var.ses_sender_email
  ses_sender_name              = var.ses_sender_name
  ses_configuration_set        = var.ses_configuration_set
  password_reset_template_name = var.ses_sender_email != "" ? module.notifications[0].password_reset_template_name : ""
  password_reset_token_ttl     = var.password_reset_token_ttl
  password_reset_page_url      = var.password_reset_page_url

  # Password policy
  password_min_length        = var.password_min_length
  password_require_uppercase = var.password_require_uppercase
  password_require_lowercase = var.password_require_lowercase
  password_require_number    = var.password_require_number
  password_require_special   = var.password_require_special

  # Brute force protection
  max_failed_login_attempts = var.max_failed_login_attempts
  lockout_duration_seconds  = var.lockout_duration_seconds
}

module "auth_mfa_totp" {
  source = "../../modules/strategies/auth_mfa_totp"
  count  = var.enable_mfa_totp_strategy ? 1 : 0

  project_name                = var.project_name
  environment                 = var.environment
  dynamodb_table_name         = module.dynamodb_core.table_name
  dynamodb_table_arn          = module.dynamodb_core.table_arn
  dynamodb_encryption_key_arn = module.dynamodb_core.encryption_key_arn
  api_gateway_id              = module.networking.api_gateway_id
  api_gateway_execution_arn   = module.networking.api_gateway_execution_arn
  log_retention_days          = var.log_retention_days
  brand_name                  = var.brand_name

  # TOTP configuration
  totp_issuer        = var.totp_issuer
  totp_digits        = var.totp_digits
  totp_period        = var.totp_period
  totp_window        = var.totp_window
  backup_codes_count = var.backup_codes_count
}

module "auth_saml" {
  source = "../../modules/strategies/auth_saml"
  count  = var.enable_saml_strategy ? 1 : 0

  project_name                   = var.project_name
  environment                    = var.environment
  dynamodb_table_name            = module.dynamodb_core.table_name
  dynamodb_table_arn             = module.dynamodb_core.table_arn
  dynamodb_encryption_key_arn    = module.dynamodb_core.encryption_key_arn
  api_gateway_id                 = module.networking.api_gateway_id
  api_gateway_execution_arn      = module.networking.api_gateway_execution_arn
  entity_id                      = local.issuer
  assertion_consumer_service_url = "${local.issuer}/auth/saml/callback"
  issuer                         = local.issuer
  log_retention_days             = var.log_retention_days
}

# ==============================================================================
# Governance Modules
# ==============================================================================

module "client_registry" {
  source = "../../modules/governance/client_registry"

  project_name                = var.project_name
  environment                 = var.environment
  dynamodb_table_name         = module.dynamodb_core.table_name
  dynamodb_table_arn          = module.dynamodb_core.table_arn
  dynamodb_encryption_key_arn = module.dynamodb_core.encryption_key_arn
  api_gateway_id              = module.networking.api_gateway_id
  api_gateway_execution_arn   = module.networking.api_gateway_execution_arn
  issuer                      = local.issuer
  lambda_log_retention_days   = var.log_retention_days
  initial_access_token        = var.client_registration_token
  allow_open_registration     = var.allow_open_client_registration
}

module "scim_v2" {
  source = "../../modules/governance/scim_v2"

  project_name                = var.project_name
  environment                 = var.environment
  dynamodb_table_name         = module.dynamodb_core.table_name
  dynamodb_table_arn          = module.dynamodb_core.table_arn
  dynamodb_encryption_key_arn = module.dynamodb_core.encryption_key_arn
  kms_key_id                  = module.kms_keyring.key_id
  kms_key_arn                 = module.kms_keyring.key_arn
  api_gateway_id              = module.networking.api_gateway_id
  api_gateway_execution_arn   = module.networking.api_gateway_execution_arn
  issuer                      = local.issuer
  lambda_log_retention_days   = var.log_retention_days
}

module "scim_groups" {
  source = "../../modules/governance/scim_groups"

  project_name                = var.project_name
  environment                 = var.environment
  dynamodb_table_name         = module.dynamodb_core.table_name
  dynamodb_table_arn          = module.dynamodb_core.table_arn
  dynamodb_encryption_key_arn = module.dynamodb_core.encryption_key_arn
  api_gateway_id              = module.networking.api_gateway_id
  api_gateway_execution_arn   = module.networking.api_gateway_execution_arn
  issuer                      = local.issuer
  lambda_log_retention_days   = var.log_retention_days
}
