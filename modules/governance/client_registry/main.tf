# ==============================================================================
# RFC 7591/7592 Dynamic Client Registration Module
# ==============================================================================
# Lambda function for /connect/register implementing OAuth 2.0 Dynamic Client
# Registration Protocol (RFC 7591) and Management Protocol (RFC 7592).
#
# Endpoints:
#   - POST /connect/register - Create client
#   - GET /connect/register/{clientId} - Read client
#   - PUT /connect/register/{clientId} - Update client
#   - DELETE /connect/register/{clientId} - Delete client
#
# Security:
#   - POST can be protected by Initial Access Token (configurable)
#   - GET/PUT/DELETE require Registration Access Token
#   - client_secret is SHA-256 hashed before storage
#   - SOC2-compliant structured audit logging
# ==============================================================================

locals {
  function_name    = "${var.project_name}-${var.environment}-client-registry"
  lambda_role_name = "${var.project_name}-${var.environment}-client-registry-role"
  log_group_name   = "/aws/lambda/${var.project_name}-${var.environment}-client-registry"
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
    Module      = "client_registry"
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
    Module      = "client_registry"
  }
}

# ------------------------------------------------------------------------------
# DynamoDB Policy
# GetItem: Fetch Client for read/update/delete
# PutItem: Create/Update Client
# DeleteItem: Delete Client
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
          "dynamodb:DeleteItem"
        ]
        Resource = var.dynamodb_table_arn
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

data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = local.dist_dir
  output_path = "${path.module}/.terraform/client-registry.zip"

  depends_on = [null_resource.build]
}

resource "aws_lambda_function" "client_registry" {
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
    Module      = "client_registry"
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

resource "aws_apigatewayv2_integration" "client_registry" {
  api_id                 = var.api_gateway_id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.client_registry.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

# POST /connect/register - Create client
resource "aws_apigatewayv2_route" "register_create" {
  api_id    = var.api_gateway_id
  route_key = "POST /connect/register"
  target    = "integrations/${aws_apigatewayv2_integration.client_registry.id}"
}

# GET /connect/register/{clientId} - Read client
resource "aws_apigatewayv2_route" "register_read" {
  api_id    = var.api_gateway_id
  route_key = "GET /connect/register/{clientId}"
  target    = "integrations/${aws_apigatewayv2_integration.client_registry.id}"
}

# PUT /connect/register/{clientId} - Update client
resource "aws_apigatewayv2_route" "register_update" {
  api_id    = var.api_gateway_id
  route_key = "PUT /connect/register/{clientId}"
  target    = "integrations/${aws_apigatewayv2_integration.client_registry.id}"
}

# DELETE /connect/register/{clientId} - Delete client
resource "aws_apigatewayv2_route" "register_delete" {
  api_id    = var.api_gateway_id
  route_key = "DELETE /connect/register/{clientId}"
  target    = "integrations/${aws_apigatewayv2_integration.client_registry.id}"
}

# OPTIONS for CORS preflight
resource "aws_apigatewayv2_route" "register_options" {
  api_id    = var.api_gateway_id
  route_key = "OPTIONS /connect/register"
  target    = "integrations/${aws_apigatewayv2_integration.client_registry.id}"
}

resource "aws_apigatewayv2_route" "register_options_client" {
  api_id    = var.api_gateway_id
  route_key = "OPTIONS /connect/register/{clientId}"
  target    = "integrations/${aws_apigatewayv2_integration.client_registry.id}"
}

resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.client_registry.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${var.api_gateway_execution_arn}/*/*"
}
