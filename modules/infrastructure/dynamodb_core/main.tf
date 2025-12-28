# ==============================================================================
# DynamoDB Core Module
# ==============================================================================
# Single Table Design implementation for OAuth 2.1 Authorization Server.
# Stores all entities: Users, Clients, Authorization Codes, Tokens, Sessions.
#
# ARCHITECTURE
# ------------
# - PAY_PER_REQUEST: True serverless scaling without capacity planning
# - DynamoDB Streams: Enabled for Global Tables multi-region replication
# - Encryption: Customer-managed symmetric KMS key (SOC2 compliant)
# - TTL: Automatic cleanup of expired tokens and sessions
#
# KEY SCHEMA (Single Table Design)
# --------------------------------
# Primary Key:
#   PK (Partition Key) - Entity identifier (e.g., USER#<id>, CLIENT#<id>)
#   SK (Sort Key)      - Entity type/relation (CONFIG, PROFILE, METADATA)
#
# GSI1 (Global Secondary Index) - Reverse Lookups:
#   GSI1PK - Lookup key (e.g., EMAIL#<email>, CLIENTS)
#   GSI1SK - Sort key for range queries
#
# GSI2 (Global Secondary Index) - Token Family Lookups:
#   GSI2PK - Family identifier (FAMILY#<family_id>)
#   GSI2SK - Sort key for ordering (REFRESH#<timestamp>)
#
# ACCESS PATTERNS (OAuth 2.1 Compliant)
# -------------------------------------
# | Operation                | Key Condition                              |
# |--------------------------|-------------------------------------------|
# | Get user by ID           | PK = USER#<id>, SK = PROFILE              |
# | Get user by email        | GSI1: GSI1PK = EMAIL#<email>              |
# | Get client by ID         | PK = CLIENT#<id>, SK = CONFIG             |
# | List all clients         | GSI1: GSI1PK = CLIENTS                    |
# | Get authorization code   | PK = CODE#<code>, SK = METADATA           |
# | Get refresh token        | PK = REFRESH#<jti>, SK = METADATA         |
# | Get session              | PK = SESSION#<id>, SK = METADATA          |
# | Get PKCE code_challenge  | PK = CODE#<code>, SK = METADATA (attr)    |
# | Revoke token family      | GSI2: GSI2PK = FAMILY#<family_id>         |
#
# TTL ATTRIBUTE
# -------------
# Items with 'ttl' attribute (Unix epoch timestamp) are automatically deleted
# after expiration per OAuth 2.1 Section 4.1.2:
#   - Authorization codes: 10 minutes maximum (MUST be short-lived)
#   - Refresh tokens: Configurable (server policy)
#   - Login sessions: Configurable (server policy)
#
# COMPLIANCE
# ----------
# - SOC2: Point-in-time recovery, encryption at rest, deletion protection
# - GDPR: TTL enables automatic data cleanup per retention policies
# - OAuth 2.1: PKCE storage, single-use authorization codes
#
# SECURITY CONSIDERATIONS
# -----------------------
# - Customer-managed KMS key with automatic rotation
# - Key policy restricts access to account root and DynamoDB service
# - No cross-account access permitted
# - Deletion protection prevents accidental data loss
#
# REFERENCES
# ----------
# - OAuth 2.1: draft-ietf-oauth-v2-1-14 Section 4.1
# - DynamoDB Single Table Design: https://www.alexdebrie.com/posts/dynamodb-single-table/
# ==============================================================================

data "aws_caller_identity" "current" {}

locals {
  table_name = "${var.project_name}-${var.environment}-core"
}

# ==============================================================================
# KMS Key - DynamoDB Encryption
# ==============================================================================
# Symmetric key for DynamoDB server-side encryption (SSE-KMS).
# Separate from the asymmetric JWT signing key in kms_keyring module.
#
# Key Properties:
# - Type: Symmetric (ENCRYPT_DECRYPT) - required by DynamoDB
# - Rotation: Automatic annual rotation enabled
# - Deletion: Configurable waiting period (7-30 days)
# ==============================================================================

resource "aws_kms_key" "dynamodb_encryption" {
  description             = "DynamoDB encryption key for ${var.project_name} (${var.environment})"
  deletion_window_in_days = var.kms_key_deletion_window_days
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "dynamodb-encryption-key-policy"
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
        Sid    = "AllowDynamoDBService"
        Effect = "Allow"
        Principal = {
          Service = "dynamodb.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id
          }
          StringLike = {
            "kms:ViaService" = "dynamodb.*.amazonaws.com"
          }
        }
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
          Bool = {
            "aws:PrincipalIsAWSService" = "false"
          }
        }
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-${var.environment}-dynamodb-encryption"
    Environment = var.environment
    Module      = "dynamodb_core"
    Purpose     = "dynamodb-encryption"
  }
}

resource "aws_kms_alias" "dynamodb_encryption" {
  name          = "alias/${var.project_name}-${var.environment}-dynamodb"
  target_key_id = aws_kms_key.dynamodb_encryption.key_id
}

# ==============================================================================
# DynamoDB Table - Single Table Design
# ==============================================================================

resource "aws_dynamodb_table" "main" {
  name         = local.table_name
  billing_mode = "PAY_PER_REQUEST"

  # Primary Key Schema
  hash_key  = "PK"
  range_key = "SK"

  attribute {
    name = "PK"
    type = "S"
  }

  attribute {
    name = "SK"
    type = "S"
  }

  # GSI1 - Reverse lookup index for email lookups and listing operations
  attribute {
    name = "GSI1PK"
    type = "S"
  }

  attribute {
    name = "GSI1SK"
    type = "S"
  }

  # GSI2 - Token family index for efficient family-wide revocation
  attribute {
    name = "GSI2PK"
    type = "S"
  }

  attribute {
    name = "GSI2SK"
    type = "S"
  }

  global_secondary_index {
    name            = "GSI1"
    hash_key        = "GSI1PK"
    range_key       = "GSI1SK"
    projection_type = "ALL"
  }

  # GSI2 - Token Family Index
  # Enables efficient revocation of all tokens in a family when replay attack detected
  # Key Pattern: GSI2PK = FAMILY#<family_id>, GSI2SK = REFRESH#<timestamp>
  global_secondary_index {
    name            = "GSI2"
    hash_key        = "GSI2PK"
    range_key       = "GSI2SK"
    projection_type = "ALL"
  }

  # DynamoDB Streams - Required for Global Tables replication
  stream_enabled   = true
  stream_view_type = "NEW_IMAGE"

  # TTL - Automatic cleanup of expired tokens and sessions
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  # Point-in-Time Recovery - Required for SOC2 compliance
  point_in_time_recovery {
    enabled = var.enable_point_in_time_recovery
  }

  # Server-Side Encryption with customer-managed symmetric KMS key
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.dynamodb_encryption.arn
  }

  # Deletion Protection - Prevents accidental table deletion
  deletion_protection_enabled = var.enable_deletion_protection

  tags = {
    Name        = local.table_name
    Environment = var.environment
    Module      = "dynamodb_core"
  }

  # Explicit dependency ensures KMS key exists before table creation
  depends_on = [aws_kms_key.dynamodb_encryption]
}
