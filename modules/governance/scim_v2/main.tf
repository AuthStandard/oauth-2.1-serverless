# ==============================================================================
# SCIM v2 User Provisioning Module
# ==============================================================================
# Lambda function for SCIM 2.0 (RFC 7643, RFC 7644) User Resource endpoints.
#
# Endpoints:
#   - POST /scim/v2/Users - Create user (with Enterprise Extension support)
#   - GET /scim/v2/Users/{id} - Read user
#   - PATCH /scim/v2/Users/{id} - Update user
#   - GET /scim/v2/Me - Self-service profile retrieval (RFC 7644 Section 3.11)
#   - PATCH /scim/v2/Me - Self-service profile update (limited fields)
#
# Enterprise Extension (RFC 7643 Section 4.3):
#   - urn:ietf:params:scim:schemas:extension:enterprise:2.0:User
#   - Supports: employeeNumber, costCenter, organization, division, department, manager
#
# Security:
#   - Admin endpoints require Bearer token authentication
#   - /Me endpoints use User Access Token (extracts sub from JWT)
#   - /Me restricts updates to safe fields only (name, locale, zoneinfo)
#   - Token revocation on user deactivation
#   - SOC2-compliant structured audit logging
#
# Build Process:
#   Terraform triggers npm build via null_resource when source files change.
#   No manual build steps required - just run `make apply`.
# ==============================================================================

locals {
  function_name    = "${var.project_name}-${var.environment}-scim-users"
  lambda_role_name = "${var.project_name}-${var.environment}-scim-users-role"
  log_group_name   = "/aws/lambda/${var.project_name}-${var.environment}-scim-users"
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
    Module      = "scim_v2"
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
    Module      = "scim_v2"
  }
}

# ------------------------------------------------------------------------------
# DynamoDB Policy
# PutItem: Create user
# GetItem: Read user
# UpdateItem: Update user status
# Query: Check email uniqueness (GSI1), revoke refresh tokens (GSI1)
# ------------------------------------------------------------------------------

resource "aws_iam_role_policy" "lambda_dynamodb" {
  name = "${local.function_name}-dynamodb"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadWriteItems"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem"
        ]
        Resource = var.dynamodb_table_arn
      },
      {
        Sid    = "QueryIndexes"
        Effect = "Allow"
        Action = [
          "dynamodb:Query"
        ]
        Resource = [
          "${var.dynamodb_table_arn}/index/GSI1"
        ]
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# KMS Policy (Encrypt/Decrypt for DynamoDB)
# ------------------------------------------------------------------------------

resource "aws_iam_role_policy" "lambda_kms" {
  name = "${local.function_name}-kms"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
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

data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = local.dist_dir
  output_path = "${path.module}/.terraform/scim-users.zip"

  depends_on = [null_resource.build]
}

resource "aws_lambda_function" "scim_users" {
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
      ISSUER     = var.issuer
    }
  }

  tags = {
    Name        = local.function_name
    Environment = var.environment
    Module      = "scim_v2"
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

resource "aws_apigatewayv2_integration" "scim_users" {
  api_id                 = var.api_gateway_id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.scim_users.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

# POST /scim/v2/Users - Create user
resource "aws_apigatewayv2_route" "scim_users_post" {
  api_id    = var.api_gateway_id
  route_key = "POST /scim/v2/Users"
  target    = "integrations/${aws_apigatewayv2_integration.scim_users.id}"
}

# GET /scim/v2/Users/{id} - Read user
resource "aws_apigatewayv2_route" "scim_users_get" {
  api_id    = var.api_gateway_id
  route_key = "GET /scim/v2/Users/{id}"
  target    = "integrations/${aws_apigatewayv2_integration.scim_users.id}"
}

# PATCH /scim/v2/Users/{id} - Update user
resource "aws_apigatewayv2_route" "scim_users_patch" {
  api_id    = var.api_gateway_id
  route_key = "PATCH /scim/v2/Users/{id}"
  target    = "integrations/${aws_apigatewayv2_integration.scim_users.id}"
}

# OPTIONS routes for CORS preflight
resource "aws_apigatewayv2_route" "scim_users_options" {
  api_id    = var.api_gateway_id
  route_key = "OPTIONS /scim/v2/Users"
  target    = "integrations/${aws_apigatewayv2_integration.scim_users.id}"
}

resource "aws_apigatewayv2_route" "scim_users_id_options" {
  api_id    = var.api_gateway_id
  route_key = "OPTIONS /scim/v2/Users/{id}"
  target    = "integrations/${aws_apigatewayv2_integration.scim_users.id}"
}

# ==============================================================================
# /Me Endpoint Routes (RFC 7644 Section 3.11)
# ==============================================================================
# Self-service profile management using User Access Token (not Admin Token).
# Extracts user identity from JWT 'sub' claim.

# GET /scim/v2/Me - Retrieve authenticated user's profile
resource "aws_apigatewayv2_route" "scim_me_get" {
  api_id    = var.api_gateway_id
  route_key = "GET /scim/v2/Me"
  target    = "integrations/${aws_apigatewayv2_integration.scim_users.id}"
}

# PATCH /scim/v2/Me - Update authenticated user's profile (limited fields)
resource "aws_apigatewayv2_route" "scim_me_patch" {
  api_id    = var.api_gateway_id
  route_key = "PATCH /scim/v2/Me"
  target    = "integrations/${aws_apigatewayv2_integration.scim_users.id}"
}

# OPTIONS /scim/v2/Me - CORS preflight
resource "aws_apigatewayv2_route" "scim_me_options" {
  api_id    = var.api_gateway_id
  route_key = "OPTIONS /scim/v2/Me"
  target    = "integrations/${aws_apigatewayv2_integration.scim_users.id}"
}

resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scim_users.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${var.api_gateway_execution_arn}/*/*"
}
