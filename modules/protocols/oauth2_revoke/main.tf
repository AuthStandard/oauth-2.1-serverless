# ==============================================================================
# OAuth 2.1 Token Revocation Endpoint Module
# ==============================================================================
# Lambda function for POST /revoke implementing RFC 7009.
#
# Use Cases:
#   - User logout: Revoke refresh token to end session
#   - Security incident: Revoke compromised tokens
#   - Token cleanup: Revoke unused tokens
#
# Security:
#   - Client authentication required for confidential clients
#   - Always returns 200 OK (prevents token enumeration)
# ==============================================================================

locals {
  function_name    = "${var.project_name}-${var.environment}-oauth-revoke"
  lambda_role_name = "${var.project_name}-${var.environment}-oauth-revoke-role"
  log_group_name   = "/aws/lambda/${var.project_name}-${var.environment}-oauth-revoke"
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
    Module      = "oauth2_revoke"
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
    Module      = "oauth2_revoke"
  }
}

# ------------------------------------------------------------------------------
# DynamoDB Policy (Get client, Get/Update refresh tokens)
# ------------------------------------------------------------------------------

resource "aws_iam_role_policy" "lambda_dynamodb" {
  name = "${local.function_name}-dynamodb"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "GetItems"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem"
        ]
        Resource = var.dynamodb_table_arn
      },
      {
        Sid    = "UpdateRefreshToken"
        Effect = "Allow"
        Action = [
          "dynamodb:UpdateItem"
        ]
        Resource = var.dynamodb_table_arn
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# KMS Policy (Decrypt for DynamoDB)
# ------------------------------------------------------------------------------

resource "aws_iam_role_policy" "lambda_kms" {
  name = "${local.function_name}-kms"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DecryptDynamoDBData"
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
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

data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = local.dist_dir
  output_path = "${path.module}/.terraform/revoke.zip"

  depends_on = [null_resource.build]
}

resource "aws_lambda_function" "revoke" {
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
      TABLE_NAME = var.dynamodb_table_name
    }
  }

  tags = {
    Name        = local.function_name
    Environment = var.environment
    Module      = "oauth2_revoke"
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

resource "aws_apigatewayv2_integration" "revoke" {
  api_id                 = var.api_gateway_id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.revoke.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "revoke" {
  api_id    = var.api_gateway_id
  route_key = "POST /revoke"
  target    = "integrations/${aws_apigatewayv2_integration.revoke.id}"
}

resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.revoke.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${var.api_gateway_execution_arn}/*/*"
}
