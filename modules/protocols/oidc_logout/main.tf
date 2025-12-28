# ==============================================================================
# OIDC RP-Initiated Logout Endpoint Module
# ==============================================================================
# Lambda function for GET /connect/logout implementing OIDC RP-Initiated Logout 1.0.
#
# Enables Relying Parties to request user logout from the Authorization Server.
# Terminates user sessions and clears session cookies.
#
# Security Features:
#   - ID token signature verification using KMS
#   - post_logout_redirect_uri validation against client registration
#   - Session deletion from DynamoDB
#   - HttpOnly session cookie clearing
#   - SOC2-compliant structured audit logging
#
# Build Process:
#   Terraform triggers npm build via null_resource when source files change.
#   No manual build steps required - just run `make apply`.
#
# @see https://openid.net/specs/openid-connect-rpinitiated-1_0.html
# ==============================================================================

locals {
  function_name    = "${var.project_name}-${var.environment}-oidc-logout"
  lambda_role_name = "${var.project_name}-${var.environment}-oidc-logout-role"
  log_group_name   = "/aws/lambda/${var.project_name}-${var.environment}-oidc-logout"
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
    Module      = "oidc_logout"
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
    Module      = "oidc_logout"
  }
}

# ------------------------------------------------------------------------------
# DynamoDB Policy
# Operations:
#   - GetItem: Fetch client configuration for redirect URI validation
#   - DeleteItem: Delete specific session by ID
#   - Query: Find all sessions for a user (GSI1)
#   - BatchWriteItem: Batch delete user sessions
# ------------------------------------------------------------------------------

resource "aws_iam_role_policy" "lambda_dynamodb" {
  name = "${local.function_name}-dynamodb"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "GetClientConfig"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem"
        ]
        Resource = var.dynamodb_table_arn
      },
      {
        Sid    = "DeleteSession"
        Effect = "Allow"
        Action = [
          "dynamodb:DeleteItem"
        ]
        Resource = var.dynamodb_table_arn
      },
      {
        Sid    = "QueryUserSessions"
        Effect = "Allow"
        Action = [
          "dynamodb:Query"
        ]
        Resource = "${var.dynamodb_table_arn}/index/GSI1"
      },
      {
        Sid    = "BatchDeleteSessions"
        Effect = "Allow"
        Action = [
          "dynamodb:BatchWriteItem"
        ]
        Resource = var.dynamodb_table_arn
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# KMS Policy
# Operations:
#   - GetPublicKey: Retrieve public key for JWT signature verification
#   - Encrypt/Decrypt/GenerateDataKey: DynamoDB with customer-managed KMS key
# ------------------------------------------------------------------------------

resource "aws_iam_role_policy" "lambda_kms" {
  name = "${local.function_name}-kms"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "GetPublicKeyForJWTVerification"
        Effect = "Allow"
        Action = [
          "kms:GetPublicKey"
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
# Build Flow:
#   1. Terraform detects source file changes via triggers
#   2. npm install fetches dependencies (including local @oauth-server/shared)
#   3. npm run build executes esbuild (see esbuild.config.mjs)
#   4. esbuild bundles src/*.ts + shared module → dist/index.js
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
    command     = "npm install && npm run build"
    working_dir = path.module
  }
}

data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = local.dist_dir
  output_path = "${path.module}/.terraform/logout.zip"

  depends_on = [null_resource.build]
}

resource "aws_lambda_function" "logout" {
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
      TABLE_NAME                  = var.dynamodb_table_name
      KMS_KEY_ID                  = var.kms_key_id
      ISSUER                      = var.issuer
      SESSION_COOKIE_NAME         = var.session_cookie_name
      SESSION_COOKIE_DOMAIN       = var.session_cookie_domain
      DEFAULT_LOGOUT_REDIRECT_URL = var.default_logout_redirect_url
    }
  }

  tags = {
    Name        = local.function_name
    Environment = var.environment
    Module      = "oidc_logout"
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

resource "aws_apigatewayv2_integration" "logout" {
  api_id                 = var.api_gateway_id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.logout.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "logout" {
  api_id    = var.api_gateway_id
  route_key = "GET /connect/logout"
  target    = "integrations/${aws_apigatewayv2_integration.logout.id}"
}

resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.logout.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${var.api_gateway_execution_arn}/*/*"
}
