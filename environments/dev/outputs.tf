# ==============================================================================
# OAuth Server - Environment Outputs
# ==============================================================================

# ------------------------------------------------------------------------------
# API Gateway
# ------------------------------------------------------------------------------

output "api_endpoint" {
  description = "Base URL of the API Gateway"
  value       = module.networking.api_endpoint
}

output "api_gateway_id" {
  description = "ID of the HTTP API Gateway"
  value       = module.networking.api_gateway_id
}

output "issuer" {
  description = "OAuth 2.1 Issuer URL"
  value       = local.issuer
}

# ------------------------------------------------------------------------------
# DynamoDB
# ------------------------------------------------------------------------------

output "dynamodb_table_name" {
  description = "Name of the DynamoDB table"
  value       = module.dynamodb_core.table_name
}

output "dynamodb_table_arn" {
  description = "ARN of the DynamoDB table"
  value       = module.dynamodb_core.table_arn
}

# ------------------------------------------------------------------------------
# KMS
# ------------------------------------------------------------------------------

output "kms_key_id" {
  description = "ID of the JWT signing key"
  value       = module.kms_keyring.key_id
}

output "kms_key_arn" {
  description = "ARN of the JWT signing key"
  value       = module.kms_keyring.key_arn
}

# ------------------------------------------------------------------------------
# OAuth 2.1 Endpoints
# ------------------------------------------------------------------------------

output "authorization_endpoint" {
  description = "OAuth 2.1 Authorization Endpoint"
  value       = "${local.issuer}/authorize"
}

output "token_endpoint" {
  description = "OAuth 2.1 Token Endpoint"
  value       = "${local.issuer}/token"
}

output "discovery_endpoint" {
  description = "OIDC Discovery Endpoint"
  value       = "${local.issuer}/.well-known/openid-configuration"
}

output "jwks_endpoint" {
  description = "JWKS Endpoint"
  value       = "${local.issuer}/keys"
}

output "userinfo_endpoint" {
  description = "OIDC UserInfo Endpoint"
  value       = "${local.issuer}/userinfo"
}

output "revocation_endpoint" {
  description = "OAuth 2.1 Token Revocation Endpoint (RFC 7009)"
  value       = "${local.issuer}/revoke"
}

output "introspection_endpoint" {
  description = "OAuth 2.1 Token Introspection Endpoint (RFC 7662)"
  value       = "${local.issuer}/introspect"
}

output "logout_endpoint" {
  description = "OIDC RP-Initiated Logout Endpoint"
  value       = "${local.issuer}/connect/logout"
}

output "registration_endpoint" {
  description = "RFC 7591 Dynamic Client Registration Endpoint"
  value       = "${local.issuer}/connect/register"
}

# ------------------------------------------------------------------------------
# API Gateway Throttling
# ------------------------------------------------------------------------------

output "throttling_burst_limit" {
  description = "API Gateway throttling burst limit (maximum concurrent requests)"
  value       = module.networking.throttling_burst_limit
}

output "throttling_rate_limit" {
  description = "API Gateway throttling rate limit (requests per second)"
  value       = module.networking.throttling_rate_limit
}
