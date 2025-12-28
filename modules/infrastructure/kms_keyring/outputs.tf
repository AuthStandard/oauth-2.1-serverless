# ==============================================================================
# KMS Keyring Module - Outputs
# ==============================================================================
# These outputs are consumed by protocol modules for JWT signing:
#   - key_arn: IAM policy Resource for kms:Sign and kms:GetPublicKey permissions
#   - key_id: Lambda environment variable for KMS SDK calls
#   - key_alias_name: Human-readable reference for documentation
#
# OIDC/JWT Integration:
#   - Token endpoint uses key_id for kms:Sign operations (RS256)
#   - JWKS endpoint (/keys) uses key_id for kms:GetPublicKey to expose public key
#   - JWT 'kid' header is passed separately via terraform.tfvars (not AWS key_id)
#     to allow stable identifiers across key rotation
#
# Usage in Protocol Modules:
#   module "oauth2_token" {
#     kms_key_id  = module.kms_keyring.key_id
#     kms_key_arn = module.kms_keyring.key_arn
#     key_id      = var.jwt_key_id  # JWT kid from terraform.tfvars
#   }
#
#   module "oidc_discovery" {
#     kms_key_id  = module.kms_keyring.key_id
#     kms_key_arn = module.kms_keyring.key_arn
#     key_id      = var.jwt_key_id  # JWT kid from terraform.tfvars
#   }
# ==============================================================================

output "key_arn" {
  description = "KMS key ARN for IAM policy kms:Sign and kms:GetPublicKey permissions"
  value       = aws_kms_key.jwt_signing.arn
}

output "key_id" {
  description = "KMS key ID for Lambda KMS_KEY_ID environment variable. Used in kms:Sign and kms:GetPublicKey API calls. NOTE: This is the AWS key ID, not the JWT 'kid' header value."
  value       = aws_kms_key.jwt_signing.key_id
}

output "key_alias_name" {
  description = "KMS key alias name (e.g., alias/oauth-server-dev-jwt-signing)"
  value       = aws_kms_alias.jwt_signing.name
}

output "key_alias_arn" {
  description = "KMS key alias ARN for IAM policies that reference the alias"
  value       = aws_kms_alias.jwt_signing.arn
}
