# ==============================================================================
# OAuth 2.1 Token Endpoint Module
# ==============================================================================
# Lambda function for POST /token implementing OAuth 2.1 (draft-ietf-oauth-v2-1-14).
#
# Supported Grant Types:
#   - Authorization Code (Section 4.1.3) with mandatory PKCE
#   - Refresh Token (Section 4.3) with rotation
#   - Client Credentials (Section 4.2)
#
# Security Features:
#   - Constant-time secret comparison (timing attack prevention)
#   - PKCE verification (S256 only)
#   - Refresh token rotation with family tracking
#   - SOC2-compliant structured audit logging
#
# Build Process:
#   Terraform triggers npm build via null_resource when source files change.
#   No manual build steps required - just run `make apply`.
# ==============================================================================

locals {
  function_name    = "${var.project_name}-${var.environment}-oauth-token"
  lambda_role_name = "${var.project_name}-${var.environment}-oauth-token-role"
  log_group_name   = "/aws/lambda/${var.project_name}-${var.environment}-oauth-token"
  source_dir       = "${path.module}/src"
  dist_dir         = "${path.module}/dist"
}

# ==============================================================================
# IAM Role for Lambda
# ==============================================================================

resource "aws_iam_role" "lambda_role" {
  name = local.lambda_role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = local.lambda_role_name
    Environment = var.environment
    Module      = "oauth2_token"
  }
}

# ------------------------------------------------------------------------------
# CloudWatch Logs Policy
# ------------------------------------------------------------------------------

resource "aws_iam_role_policy" "lambda_logs" {
  name = "${local.function_name}-logs"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.lambda.arn}:*"
      }
    ]
  })
}

# ==============================================================================
# CloudWatch Log Group (SOC2 Compliant)
# ==============================================================================

resource "aws_cloudwatch_log_group" "lambda" {
  name              = local.log_group_name
  retention_in_days = var.lambda_log_retention_days

  tags = {
    Name        = local.log_group_name
    Environment = var.environment
    Module      = "oauth2_token"
  }
}

# ------------------------------------------------------------------------------
# DynamoDB Policy (Minimal Permissions)
# GetItem: Fetch Authorization Code, User, Client, Refresh Token
# PutItem: Store Refresh Token
# UpdateItem: Mark auth code as used, rotate refresh token
# Query: Query refresh tokens by family (for revocation), user groups (for RBAC)
# ------------------------------------------------------------------------------

resource "aws_iam_role_policy" "lambda_dynamodb" {
  name = "${local.function_name}-dynamodb"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadItems"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem"
        ]
        Resource = var.dynamodb_table_arn
      },
      {
        Sid    = "WriteItems"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:UpdateItem"
        ]
        Resource = var.dynamodb_table_arn
      },
      {
        Sid    = "QueryTable"
        Effect = "Allow"
        Action = [
          "dynamodb:Query"
        ]
        Resource = var.dynamodb_table_arn
      },
      {
        Sid    = "QueryTokenFamily"
        Effect = "Allow"
        Action = [
          "dynamodb:Query"
        ]
        Resource = [
          "${var.dynamodb_table_arn}/index/GSI2"
        ]
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# KMS Policy (Sign for JWT, Encrypt/Decrypt for DynamoDB)
# Sign: Required for JWT token signing with asymmetric KMS key
# Encrypt/Decrypt: Required when DynamoDB uses customer-managed KMS key
# ------------------------------------------------------------------------------

resource "aws_iam_role_policy" "lambda_kms" {
  name = "${local.function_name}-kms"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SignJWT"
        Effect = "Allow"
        Action = [
          "kms:Sign"
        ]
        Resource = var.kms_key_arn
      },
      {
        Sid    = "EncryptDecryptDynamoDBData"
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = var.dynamodb_encryption_key_arn
      }
    ]
  })
}

# ==============================================================================
# Lambda Function Build
# ==============================================================================
#
# BUILD ARCHITECTURE:
# This module uses esbuild to bundle TypeScript code into a single JavaScript file.
# The build process is triggered automatically when source files change.
#
# Why esbuild?
#   1. Bundles @oauth-server/shared into the Lambda package (no Lambda Layers needed)
#   2. Tree-shakes unused code for smaller bundles and faster cold starts
#   3. 10-100x faster than webpack - enables rapid iteration
#   4. Industry standard: used by AWS SAM, SST, Serverless Framework, CDK
#
# Build Flow:
#   1. Terraform detects source file changes via triggers
#   2. npm install fetches dependencies (including local @oauth-server/shared)
#   3. npm run build executes esbuild (see esbuild.config.mjs)
#   4. esbuild bundles src/index.ts + shared module → dist/index.js
#   5. archive_file zips dist/ for Lambda deployment
#
# IMPORTANT: The shared module (../../shared) is bundled at build time.
# Changes to shared module require rebuilding this Lambda.
# The shared_hash trigger ensures rebuilds when shared code changes.
#
# ==============================================================================

resource "null_resource" "build" {
  triggers = {
    # Rebuild when local source files change
    source_hash = sha256(join("", [for f in fileset(local.source_dir, "**/*.ts") : filesha256("${local.source_dir}/${f}")]))

    # Rebuild when package.json changes (dependencies updated)
    package_json = filesha256("${path.module}/package.json")

    # Rebuild when shared module changes (bundled into this Lambda)
    shared_hash = sha256(join("", [for f in fileset("${path.module}/../../shared/src", "**/*.ts") : filesha256("${path.module}/../../shared/src/${f}")]))

    # Rebuild when esbuild config changes
    esbuild_config = filesha256("${path.module}/esbuild.config.mjs")
  }

  provisioner "local-exec" {
    # npm install: Fetches dependencies including local @oauth-server/shared
    # npm run build: Executes esbuild to bundle TypeScript → JavaScript
    command     = "npm install && npm run build"
    working_dir = path.module
  }
}

# Archive the built Lambda code (includes all grant handlers)
data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = local.dist_dir
  output_path = "${path.module}/.terraform/token.zip"

  depends_on = [null_resource.build]
}

resource "aws_lambda_function" "token" {
  function_name = local.function_name
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size

  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  environment {
    variables = {
      TABLE_NAME        = var.dynamodb_table_name
      KMS_KEY_ID        = var.kms_key_id
      KEY_ID            = var.key_id
      ISSUER            = var.issuer
      ACCESS_TOKEN_TTL  = tostring(var.default_access_token_ttl)
      ID_TOKEN_TTL      = tostring(var.default_id_token_ttl)
      REFRESH_TOKEN_TTL = tostring(var.default_refresh_token_ttl)
      ALLOWED_ORIGINS   = join(",", var.allowed_origins)
    }
  }

  tags = {
    Name        = local.function_name
    Environment = var.environment
    Module      = "oauth2_token"
  }

  depends_on = [
    aws_iam_role_policy.lambda_logs,
    aws_iam_role_policy.lambda_dynamodb,
    aws_iam_role_policy.lambda_kms,
    aws_cloudwatch_log_group.lambda,
    null_resource.build,
  ]
}

# ==============================================================================
# API Gateway Integration
# ==============================================================================

resource "aws_apigatewayv2_integration" "token" {
  api_id                 = var.api_gateway_id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.token.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "token" {
  api_id    = var.api_gateway_id
  route_key = "POST /token"
  target    = "integrations/${aws_apigatewayv2_integration.token.id}"
}

# OPTIONS route for CORS preflight requests
resource "aws_apigatewayv2_route" "token_options" {
  api_id    = var.api_gateway_id
  route_key = "OPTIONS /token"
  target    = "integrations/${aws_apigatewayv2_integration.token.id}"
}

resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.token.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${var.api_gateway_execution_arn}/*/*"
}
