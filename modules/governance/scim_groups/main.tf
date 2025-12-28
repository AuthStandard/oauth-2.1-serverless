# ==============================================================================
# SCIM v2 Group Provisioning Module
# ==============================================================================
# Lambda function for SCIM 2.0 (RFC 7643, RFC 7644) Group Resource endpoints.
#
# Endpoints:
#   - POST /scim/v2/Groups - Create group
#   - GET /scim/v2/Groups - List groups
#   - GET /scim/v2/Groups/{id} - Read group
#   - PATCH /scim/v2/Groups/{id} - Update group (add/remove members)
#   - DELETE /scim/v2/Groups/{id} - Delete group
#
# DynamoDB Key Patterns (Adjacency List for Group Membership):
#   - Group:          PK=GROUP#<id>       SK=METADATA
#   - Membership:     PK=GROUP#<id>       SK=MEMBER#<user_id>
#   - Reverse Lookup: PK=USER#<user_id>   SK=GROUP#<group_id>
#
# Security:
#   - All endpoints require Bearer token authentication
#   - TransactWriteItems for atomic membership operations
#   - SOC2-compliant structured audit logging
#
# Build Process:
#   Terraform triggers npm build via null_resource when source files change.
#   No manual build steps required - just run `make apply`.
# ==============================================================================

locals {
  function_name    = "${var.project_name}-${var.environment}-scim-groups"
  lambda_role_name = "${var.project_name}-${var.environment}-scim-groups-role"
  log_group_name   = "/aws/lambda/${var.project_name}-${var.environment}-scim-groups"
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
    Module      = "scim_groups"
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
    Module      = "scim_groups"
  }
}

# ------------------------------------------------------------------------------
# DynamoDB Policy
# GetItem: Read group, user info for denormalization
# PutItem: Create group, membership items
# UpdateItem: Update group metadata
# DeleteItem: Delete group, membership items
# Query: List groups (GSI1), list members, check membership
# TransactWriteItems: Atomic group creation/deletion with members
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
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem"
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
          var.dynamodb_table_arn,
          "${var.dynamodb_table_arn}/index/GSI1"
        ]
      },
      {
        Sid    = "TransactWriteItems"
        Effect = "Allow"
        Action = [
          "dynamodb:TransactWriteItems"
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
  output_path = "${path.module}/.terraform/scim-groups.zip"

  depends_on = [null_resource.build]
}

resource "aws_lambda_function" "scim_groups" {
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
    Module      = "scim_groups"
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

resource "aws_apigatewayv2_integration" "scim_groups" {
  api_id                 = var.api_gateway_id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.scim_groups.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

# POST /scim/v2/Groups - Create group
resource "aws_apigatewayv2_route" "scim_groups_post" {
  api_id    = var.api_gateway_id
  route_key = "POST /scim/v2/Groups"
  target    = "integrations/${aws_apigatewayv2_integration.scim_groups.id}"
}

# GET /scim/v2/Groups - List groups
resource "aws_apigatewayv2_route" "scim_groups_list" {
  api_id    = var.api_gateway_id
  route_key = "GET /scim/v2/Groups"
  target    = "integrations/${aws_apigatewayv2_integration.scim_groups.id}"
}

# GET /scim/v2/Groups/{id} - Read group
resource "aws_apigatewayv2_route" "scim_groups_get" {
  api_id    = var.api_gateway_id
  route_key = "GET /scim/v2/Groups/{id}"
  target    = "integrations/${aws_apigatewayv2_integration.scim_groups.id}"
}

# PATCH /scim/v2/Groups/{id} - Update group
resource "aws_apigatewayv2_route" "scim_groups_patch" {
  api_id    = var.api_gateway_id
  route_key = "PATCH /scim/v2/Groups/{id}"
  target    = "integrations/${aws_apigatewayv2_integration.scim_groups.id}"
}

# DELETE /scim/v2/Groups/{id} - Delete group
resource "aws_apigatewayv2_route" "scim_groups_delete" {
  api_id    = var.api_gateway_id
  route_key = "DELETE /scim/v2/Groups/{id}"
  target    = "integrations/${aws_apigatewayv2_integration.scim_groups.id}"
}

# OPTIONS routes for CORS preflight
resource "aws_apigatewayv2_route" "scim_groups_options" {
  api_id    = var.api_gateway_id
  route_key = "OPTIONS /scim/v2/Groups"
  target    = "integrations/${aws_apigatewayv2_integration.scim_groups.id}"
}

resource "aws_apigatewayv2_route" "scim_groups_id_options" {
  api_id    = var.api_gateway_id
  route_key = "OPTIONS /scim/v2/Groups/{id}"
  target    = "integrations/${aws_apigatewayv2_integration.scim_groups.id}"
}

resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scim_groups.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${var.api_gateway_execution_arn}/*/*"
}
