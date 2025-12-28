# ==============================================================================
# KMS Keyring Module
# ==============================================================================
# Asymmetric RSA key for JWT signing using RS256 algorithm (RFC 7518).
#
# ARCHITECTURE
# ------------
# - Key Type: RSA_2048 asymmetric key pair
# - Usage: SIGN_VERIFY only (cannot encrypt/decrypt)
# - Security: Private key never leaves AWS KMS HSM boundary (FIPS 140-2 Level 3)
# - Audit: All signing operations logged to CloudTrail
#
# KEY ROTATION (Manual Process Required)
# --------------------------------------
# AWS does NOT support automatic rotation for asymmetric keys.
# Implement manual rotation as follows:
#
# 1. Create new KMS key (update key_id in terraform.tfvars: jwt-key-2)
# 2. Update JWKS endpoint to serve both old and new public keys
# 3. Configure token endpoint to sign with new key
# 4. Wait for maximum token lifetime to elapse (old tokens expire)
# 5. Remove old public key from JWKS endpoint
# 6. Schedule old KMS key for deletion
#
# Recommended rotation frequency: Annually or per security policy
#
# OIDC COMPLIANCE (OpenID Connect Core 1.0)
# -----------------------------------------
# - RS256 algorithm is REQUIRED by OIDC specification (Section 15.1)
# - Public key exposed via /.well-known/jwks.json endpoint
# - Key ID (kid) in JWT header enables key selection during rotation
#   NOTE: The kid is passed separately via terraform.tfvars, not derived
#   from the AWS key ID, to allow stable identifiers across key rotation.
#
# SECURITY CONSIDERATIONS
# -----------------------
# - Key policy grants account root full access (standard AWS pattern)
# - Lambda roles receive access via IAM policies, not key policy
# - No cross-account access permitted
# - Key material is generated and stored within AWS KMS HSM
#
# REFERENCES
# ----------
# - RFC 7518: JSON Web Algorithms (JWA) - Section 3.3 (RS256)
# - RFC 7517: JSON Web Key (JWK) - Section 4.5 (kid parameter)
# - OpenID Connect Core 1.0: Section 15.1 (Signing)
# - OAuth 2.1: draft-ietf-oauth-v2-1-14
# ==============================================================================

data "aws_caller_identity" "current" {}

locals {
  key_alias = "alias/${var.project_name}-${var.environment}-jwt-signing"
}

# ==============================================================================
# Asymmetric KMS Key for JWT Signing
# ==============================================================================

resource "aws_kms_key" "jwt_signing" {
  description              = "JWT signing key for ${var.project_name} (${var.environment})"
  customer_master_key_spec = "RSA_2048"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = var.key_deletion_window_days
  multi_region             = false
  # Note: enable_key_rotation is not applicable for asymmetric keys (AWS limitation).
  # See header comments for manual rotation procedure.

  # Key policy grants account root full access.
  # Lambda roles receive access via IAM policies attached to their execution roles.
  # Explicit deny prevents cross-account access for security.
  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "jwt-signing-key-policy"
    Statement = [
      {
        Sid    = "AllowAccountAdministration"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid       = "DenyExternalAccess"
        Effect    = "Deny"
        Principal = "*"
        Action    = "kms:*"
        Resource  = "*"
        Condition = {
          StringNotEquals = {
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-${var.environment}-jwt-signing"
    Environment = var.environment
    Module      = "kms_keyring"
    Purpose     = "jwt-signing"
  }
}

# ==============================================================================
# KMS Key Alias
# ==============================================================================

resource "aws_kms_alias" "jwt_signing" {
  name          = local.key_alias
  target_key_id = aws_kms_key.jwt_signing.key_id
}
