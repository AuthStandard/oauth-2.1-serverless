# ==============================================================================
# OAuth 2.1 Authorization Endpoint Module
# ==============================================================================
# Lambda functions for the authorization flow:
#   GET /authorize          -> Initiate authorization request
#   GET /authorize/callback -> Complete authorization after authentication
#
# Implements OAuth 2.1 (draft-ietf-oauth-v2-1-14) Section 4.1 with strict PKCE.
#
# Security Features:
#   - Mandatory PKCE with S256 only (OAuth 2.1 requirement)
#   - Strict redirect_uri validation (exact string match)
#   - Session TTL for automatic cleanup
#   - Issuer parameter in responses (mix-up attack mitigation)
#   - SOC2-compliant structured audit logging
#
# Build Process:
#   Terraform triggers npm build via null_resource when source files change.
#   No manual build steps required - just run `make apply`.
# ==============================================================================

locals {
  authorize_function_name = "${var.project_name}-${var.environment}-oauth-authorize"
  callback_function_name  = "${var.project_name}-${var.environment}-oauth-callback"
  lambda_role_name        = "${var.project_name}-${var.environment}-oauth-authorize-role"
  source_dir              = "${path.module}/src"
  dist_dir                = "${path.module}/dist"
}

# ==============================================================================
# CloudWatch Log Groups (SOC2 Compliant)
# ==============================================================================

resource "aws_cloudwatch_log_group" "authorize" {
  name              = "/aws/lambda/${local.authorize_function_name}"
  retention_in_days = var.lambda_log_retention_days

  tags = {
    Name        = "${local.authorize_function_name}-logs"
    Environment = var.environment
    Module      = "oauth2_authorize"
  }
}

resource "aws_cloudwatch_log_group" "callback" {
  name              = "/aws/lambda/${local.callback_function_name}"
  retention_in_days = var.lambda_log_retention_days

  tags = {
    Name        = "${local.callback_function_name}-logs"
    Environment = var.environment
    Module      = "oauth2_authorize"
  }
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
    Module      = "oauth2_authorize"
  }
}

# ------------------------------------------------------------------------------
# CloudWatch Logs Policy
# ------------------------------------------------------------------------------

resource "aws_iam_role_policy" "lambda_logs" {
  name = "${local.authorize_function_name}-logs"
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
          "${aws_cloudwatch_log_group.authorize.arn}:*",
          "${aws_cloudwatch_log_group.callback.arn}:*"
        ]
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# DynamoDB Policy (Least Privilege)
# Authorize: GetItem for CLIENT#*, PutItem for SESSION#*
# Callback: GetItem for SESSION#*, PutItem for CODE#*, DeleteItem for SESSION#*
# ------------------------------------------------------------------------------

resource "aws_iam_role_policy" "lambda_dynamodb" {
  name = "${local.authorize_function_name}-dynamodb"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadClientAndSession"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem"
        ]
        Resource = var.dynamodb_table_arn
      },
      {
        Sid    = "WriteSessionAndCode"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem"
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
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# KMS Policy (Encrypt/Decrypt for DynamoDB encryption at rest)
# Required when DynamoDB uses customer-managed KMS key
# ------------------------------------------------------------------------------

resource "aws_iam_role_policy" "lambda_kms" {
  name = "${local.authorize_function_name}-kms"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBEncryption"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = var.dynamodb_encryption_key_arn
      }
    ]
  })
}

# ==============================================================================
# Lambda Build
# ==============================================================================
# Terraform triggers npm build when source files change.
# esbuild bundles TypeScript + @oauth-server/shared into dist/*.js
# ==============================================================================

resource "null_resource" "build" {
  triggers = {
    source_hash    = sha256(join("", [for f in fileset(local.source_dir, "**/*.ts") : filesha256("${local.source_dir}/${f}")]))
    package_json   = filesha256("${path.module}/package.json")
    shared_hash    = sha256(join("", [for f in fileset("${path.module}/../../shared/src", "**/*.ts") : filesha256("${path.module}/../../shared/src/${f}")]))
    esbuild_config = filesha256("${path.module}/esbuild.config.mjs")
  }

  provisioner "local-exec" {
    command     = "npm install && npm run build"
    working_dir = path.module
  }
}

data "archive_file" "authorize_lambda" {
  type        = "zip"
  source_dir  = local.dist_dir
  output_path = "${path.module}/.terraform/authorize.zip"

  depends_on = [null_resource.build]
}

data "archive_file" "callback_lambda" {
  type        = "zip"
  source_dir  = local.dist_dir
  output_path = "${path.module}/.terraform/callback.zip"

  depends_on = [null_resource.build]
}

# ------------------------------------------------------------------------------
# Authorize Handler Lambda
# GET /authorize
# ------------------------------------------------------------------------------

resource "aws_lambda_function" "authorize" {
  function_name = local.authorize_function_name
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size

  filename         = data.archive_file.authorize_lambda.output_path
  source_code_hash = data.archive_file.authorize_lambda.output_base64sha256

  environment {
    variables = {
      TABLE_NAME          = var.dynamodb_table_name
      LOGIN_ROUTER_URL    = var.login_router_url
      SESSION_TTL_SECONDS = tostring(var.session_ttl_seconds)
      ISSUER              = var.issuer
      SESSION_COOKIE_NAME = var.session_cookie_name
      CODE_TTL_SECONDS    = tostring(var.code_ttl_seconds)
    }
  }

  tags = {
    Name        = local.authorize_function_name
    Environment = var.environment
    Module      = "oauth2_authorize"
  }

  depends_on = [
    aws_cloudwatch_log_group.authorize,
    aws_iam_role_policy.lambda_logs,
    aws_iam_role_policy.lambda_dynamodb,
    aws_iam_role_policy.lambda_kms,
    null_resource.build,
  ]
}

# ------------------------------------------------------------------------------
# Callback Handler Lambda
# GET /authorize/callback
# ------------------------------------------------------------------------------

resource "aws_lambda_function" "callback" {
  function_name = local.callback_function_name
  role          = aws_iam_role.lambda_role.arn
  handler       = "callback.handler"
  runtime       = "nodejs20.x"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size

  filename         = data.archive_file.callback_lambda.output_path
  source_code_hash = data.archive_file.callback_lambda.output_base64sha256

  environment {
    variables = {
      TABLE_NAME               = var.dynamodb_table_name
      CODE_TTL_SECONDS         = tostring(var.code_ttl_seconds)
      ISSUER                   = var.issuer
      SESSION_COOKIE_NAME      = var.session_cookie_name
      SESSION_COOKIE_DOMAIN    = var.session_cookie_domain
      AUTH_SESSION_TTL_SECONDS = tostring(var.auth_session_ttl_seconds)
    }
  }

  tags = {
    Name        = local.callback_function_name
    Environment = var.environment
    Module      = "oauth2_authorize"
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
# Authorize Route: GET /authorize
# ------------------------------------------------------------------------------

resource "aws_apigatewayv2_integration" "authorize" {
  api_id                 = var.api_gateway_id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.authorize.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "authorize" {
  api_id    = var.api_gateway_id
  route_key = "GET /authorize"
  target    = "integrations/${aws_apigatewayv2_integration.authorize.id}"
}

resource "aws_lambda_permission" "authorize_api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.authorize.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${var.api_gateway_execution_arn}/*/*"
}

# ------------------------------------------------------------------------------
# Callback Route: GET /authorize/callback
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
  route_key = "GET /authorize/callback"
  target    = "integrations/${aws_apigatewayv2_integration.callback.id}"
}

resource "aws_lambda_permission" "callback_api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.callback.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${var.api_gateway_execution_arn}/*/*"
}
