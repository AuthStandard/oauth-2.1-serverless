# ==============================================================================
# OAuth Server - OIDC Discovery Endpoint
# ==============================================================================
# Implements OpenID Connect Discovery 1.0
# Routes:
#   GET /.well-known/openid-configuration -> Provider metadata
#   GET /keys                              -> JWKS (JSON Web Key Set)
#
# Build Process:
#   Terraform triggers npm build via null_resource when source files change.
# ==============================================================================

locals {
  discovery_function_name = "${var.project_name}-${var.environment}-oidc-discovery"
  jwks_function_name      = "${var.project_name}-${var.environment}-oidc-jwks"
  lambda_role_name        = "${var.project_name}-${var.environment}-oidc-discovery-role"
  source_dir              = "${path.module}/src"
  dist_dir                = "${path.module}/dist"
}

# ==============================================================================
# CloudWatch Log Groups (SOC2 Compliant)
# ==============================================================================

resource "aws_cloudwatch_log_group" "discovery" {
  name              = "/aws/lambda/${local.discovery_function_name}"
  retention_in_days = var.lambda_log_retention_days

  tags = {
    Name        = "${local.discovery_function_name}-logs"
    Environment = var.environment
    Module      = "oidc_discovery"
  }
}

resource "aws_cloudwatch_log_group" "jwks" {
  name              = "/aws/lambda/${local.jwks_function_name}"
  retention_in_days = var.lambda_log_retention_days

  tags = {
    Name        = "${local.jwks_function_name}-logs"
    Environment = var.environment
    Module      = "oidc_discovery"
  }
}

# ==============================================================================
# IAM Role for Lambda Functions
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
    Module      = "oidc_discovery"
  }
}

# ------------------------------------------------------------------------------
# CloudWatch Logs Policy
# ------------------------------------------------------------------------------

resource "aws_iam_role_policy" "lambda_logs" {
  name = "${local.lambda_role_name}-logs"
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
        Resource = [
          "${aws_cloudwatch_log_group.discovery.arn}:*",
          "${aws_cloudwatch_log_group.jwks.arn}:*"
        ]
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# KMS Policy (for JWKS endpoint to read public key)
# ------------------------------------------------------------------------------

resource "aws_iam_role_policy" "lambda_kms" {
  name = "${local.lambda_role_name}-kms"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "GetPublicKey"
        Effect = "Allow"
        Action = [
          "kms:GetPublicKey"
        ]
        Resource = var.kms_key_arn
      }
    ]
  })
}

# ==============================================================================
# Lambda Function Build
# ==============================================================================
#
# BUILD ARCHITECTURE:
# This module uses esbuild to bundle TypeScript code into JavaScript files.
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
#   4. esbuild bundles src/*.ts + shared module → dist/*.js
#   5. archive_file zips dist/ for Lambda deployment
#
# This module has TWO Lambda handlers:
#   - index.ts → dist/index.js (GET /.well-known/openid-configuration)
#   - jwks.ts  → dist/jwks.js  (GET /keys)
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

# Archive the built Lambda code for discovery endpoint
# Both handlers share minimal code, but including full dist is simpler
# and the package size is negligible (~20KB)
data "archive_file" "discovery_lambda" {
  type        = "zip"
  source_dir  = local.dist_dir
  output_path = "${path.module}/.terraform/discovery.zip"

  depends_on = [null_resource.build]
}

# Archive the built Lambda code for JWKS endpoint
data "archive_file" "jwks_lambda" {
  type        = "zip"
  source_dir  = local.dist_dir
  output_path = "${path.module}/.terraform/jwks.zip"

  depends_on = [null_resource.build]
}

# ------------------------------------------------------------------------------
# Discovery Handler Lambda
# GET /.well-known/openid-configuration
# ------------------------------------------------------------------------------

resource "aws_lambda_function" "discovery" {
  function_name = local.discovery_function_name
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size

  filename         = data.archive_file.discovery_lambda.output_path
  source_code_hash = data.archive_file.discovery_lambda.output_base64sha256

  environment {
    variables = {
      ISSUER = var.issuer
    }
  }

  tags = {
    Name        = local.discovery_function_name
    Environment = var.environment
    Module      = "oidc_discovery"
  }

  depends_on = [
    aws_cloudwatch_log_group.discovery,
    aws_iam_role_policy.lambda_logs,
    null_resource.build,
  ]
}

# ------------------------------------------------------------------------------
# JWKS Handler Lambda
# GET /keys
# ------------------------------------------------------------------------------

resource "aws_lambda_function" "jwks" {
  function_name = local.jwks_function_name
  role          = aws_iam_role.lambda_role.arn
  handler       = "jwks.handler"
  runtime       = "nodejs20.x"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size

  filename         = data.archive_file.jwks_lambda.output_path
  source_code_hash = data.archive_file.jwks_lambda.output_base64sha256

  environment {
    variables = {
      KMS_KEY_ID = var.kms_key_id
      KEY_ID     = var.key_id
    }
  }

  tags = {
    Name        = local.jwks_function_name
    Environment = var.environment
    Module      = "oidc_discovery"
  }

  depends_on = [
    aws_cloudwatch_log_group.jwks,
    aws_iam_role_policy.lambda_logs,
    aws_iam_role_policy.lambda_kms,
    null_resource.build,
  ]
}

# ==============================================================================
# API Gateway Integration
# ==============================================================================

# ------------------------------------------------------------------------------
# Discovery Route: GET /.well-known/openid-configuration
# ------------------------------------------------------------------------------

resource "aws_apigatewayv2_integration" "discovery" {
  api_id                 = var.api_gateway_id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.discovery.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "discovery" {
  api_id    = var.api_gateway_id
  route_key = "GET /.well-known/openid-configuration"
  target    = "integrations/${aws_apigatewayv2_integration.discovery.id}"
}

resource "aws_lambda_permission" "discovery_api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.discovery.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${var.api_gateway_execution_arn}/*/*"
}

# ------------------------------------------------------------------------------
# JWKS Route: GET /keys
# ------------------------------------------------------------------------------

resource "aws_apigatewayv2_integration" "jwks" {
  api_id                 = var.api_gateway_id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.jwks.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "jwks" {
  api_id    = var.api_gateway_id
  route_key = "GET /keys"
  target    = "integrations/${aws_apigatewayv2_integration.jwks.id}"
}

resource "aws_lambda_permission" "jwks_api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.jwks.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${var.api_gateway_execution_arn}/*/*"
}
