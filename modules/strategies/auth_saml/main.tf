# ==============================================================================
# OAuth Server - SAML Authentication Strategy
# ==============================================================================
# Pluggable authentication strategy for SAML 2.0 SSO.
# Implements SP-initiated SSO flow with JIT user provisioning.
#
# Routes:
#   GET  /auth/saml/metadata  -> SP metadata XML for IdP configuration
#   POST /auth/saml/callback  -> Assertion Consumer Service (ACS)
#
# Security:
#   - XML signature validation using IdP certificate
#   - Assertion time window validation (NotBefore/NotOnOrAfter)
#   - Session binding via RelayState
#   - Audit logging for SOC2 compliance
#
# Build Process:
#   Terraform triggers npm build via null_resource when source files change.
#   Uses esbuild to bundle @oauth-server/shared into the Lambda package.
#   No manual build steps required - just run `make apply`.
# ==============================================================================

locals {
  metadata_function_name = "${var.project_name}-${var.environment}-auth-saml-metadata"
  callback_function_name = "${var.project_name}-${var.environment}-auth-saml-callback"
  lambda_role_name       = "${var.project_name}-${var.environment}-auth-saml-role"
  source_dir             = "${path.module}/src"
  dist_dir               = "${path.module}/dist"
}

# ==============================================================================
# CloudWatch Log Groups
# ==============================================================================

resource "aws_cloudwatch_log_group" "metadata" {
  name              = "/aws/lambda/${local.metadata_function_name}"
  retention_in_days = var.log_retention_days

  tags = {
    Name        = "${local.metadata_function_name}-logs"
    Environment = var.environment
    Module      = "auth_saml"
  }
}

resource "aws_cloudwatch_log_group" "callback" {
  name              = "/aws/lambda/${local.callback_function_name}"
  retention_in_days = var.log_retention_days

  tags = {
    Name        = "${local.callback_function_name}-logs"
    Environment = var.environment
    Module      = "auth_saml"
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
    Module      = "auth_saml"
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
          "${aws_cloudwatch_log_group.metadata.arn}:*",
          "${aws_cloudwatch_log_group.callback.arn}:*"
        ]
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# DynamoDB Policy (Least Privilege)
# ------------------------------------------------------------------------------

resource "aws_iam_role_policy" "lambda_dynamodb" {
  name = "${local.lambda_role_name}-dynamodb"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "GetSamlProviderAndSession"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem"
        ]
        Resource = var.dynamodb_table_arn
      },
      {
        Sid    = "QueryUserByEmail"
        Effect = "Allow"
        Action = [
          "dynamodb:Query"
        ]
        Resource = "${var.dynamodb_table_arn}/index/GSI1"
      },
      {
        Sid    = "CreateUser"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem"
        ]
        Resource = var.dynamodb_table_arn
      },
      {
        Sid    = "UpdateSession"
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
# KMS Policy (Encrypt/Decrypt for DynamoDB encryption)
# ------------------------------------------------------------------------------

resource "aws_iam_role_policy" "lambda_kms" {
  name = "${local.lambda_role_name}-kms"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EncryptDecryptDynamoDBData"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
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
# Uses esbuild to bundle TypeScript code into JavaScript files.
# The build process is triggered automatically when source files change.
#
# Why esbuild?
#   1. Bundles @oauth-server/shared into the Lambda package (no Lambda Layers)
#   2. Tree-shakes unused code for smaller bundles and faster cold starts
#   3. 10-100x faster than webpack
#   4. Industry standard: used by AWS SAM, SST, Serverless Framework, CDK
#
# Build Flow:
#   1. Terraform detects source file changes via triggers
#   2. npm install fetches dependencies (including local @oauth-server/shared)
#   3. npm run build executes esbuild (see esbuild.config.mjs)
#   4. esbuild bundles handlers + shared module → dist/*.js
#   5. archive_file zips dist/ for Lambda deployment
#
# ==============================================================================

resource "null_resource" "build" {
  triggers = {
    # Rebuild when local source files change
    source_hash = sha256(join("", [for f in fileset(local.source_dir, "**/*.ts") : filesha256("${local.source_dir}/${f}")]))

    # Rebuild when package.json changes
    package_json = filesha256("${path.module}/package.json")

    # Rebuild when shared module changes
    shared_hash = sha256(join("", [for f in fileset("${path.module}/../../shared/src", "**/*.ts") : filesha256("${path.module}/../../shared/src/${f}")]))

    # Rebuild when esbuild config changes
    esbuild_config = filesha256("${path.module}/esbuild.config.mjs")
  }

  provisioner "local-exec" {
    command     = "npm install && npm run build"
    working_dir = path.module
  }
}

# Archive the built Lambda code
data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = local.dist_dir
  output_path = "${path.module}/.terraform/auth-saml.zip"

  depends_on = [null_resource.build]
}

# ------------------------------------------------------------------------------
# SP Metadata Handler Lambda
# GET /auth/saml/metadata
# ------------------------------------------------------------------------------

resource "aws_lambda_function" "metadata" {
  function_name = local.metadata_function_name
  role          = aws_iam_role.lambda_role.arn
  handler       = "metadata.handler"
  runtime       = "nodejs20.x"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size

  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  environment {
    variables = {
      ENTITY_ID = var.entity_id
      ACS_URL   = var.assertion_consumer_service_url
      ISSUER    = var.issuer
    }
  }

  tags = {
    Name        = local.metadata_function_name
    Environment = var.environment
    Module      = "auth_saml"
  }

  depends_on = [
    aws_cloudwatch_log_group.metadata,
    aws_iam_role_policy.lambda_logs,
    null_resource.build,
  ]
}

# ------------------------------------------------------------------------------
# SAML Callback Handler Lambda
# POST /auth/saml/callback
# ------------------------------------------------------------------------------

resource "aws_lambda_function" "callback" {
  function_name = local.callback_function_name
  role          = aws_iam_role.lambda_role.arn
  handler       = "callback.handler"
  runtime       = "nodejs20.x"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size

  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  environment {
    variables = {
      TABLE_NAME   = var.dynamodb_table_name
      CALLBACK_URL = var.protocol_callback_url
      ENTITY_ID    = var.entity_id
    }
  }

  tags = {
    Name        = local.callback_function_name
    Environment = var.environment
    Module      = "auth_saml"
  }

  depends_on = [
    aws_cloudwatch_log_group.callback,
    aws_iam_role_policy.lambda_logs,
    aws_iam_role_policy.lambda_dynamodb,
    aws_iam_role_policy.lambda_kms,
    null_resource.build,
  ]
}

# ==============================================================================
# API Gateway Integration
# ==============================================================================

# ------------------------------------------------------------------------------
# Metadata Route: GET /auth/saml/metadata
# ------------------------------------------------------------------------------

resource "aws_apigatewayv2_integration" "metadata" {
  api_id                 = var.api_gateway_id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.metadata.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "metadata" {
  api_id    = var.api_gateway_id
  route_key = "GET /auth/saml/metadata"
  target    = "integrations/${aws_apigatewayv2_integration.metadata.id}"
}

resource "aws_lambda_permission" "metadata_api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.metadata.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${var.api_gateway_execution_arn}/*/*"
}

# ------------------------------------------------------------------------------
# Callback Route: POST /auth/saml/callback
# ------------------------------------------------------------------------------

resource "aws_apigatewayv2_integration" "callback" {
  api_id                 = var.api_gateway_id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.callback.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "callback" {
  api_id    = var.api_gateway_id
  route_key = "POST /auth/saml/callback"
  target    = "integrations/${aws_apigatewayv2_integration.callback.id}"
}

resource "aws_lambda_permission" "callback_api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.callback.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${var.api_gateway_execution_arn}/*/*"
}
