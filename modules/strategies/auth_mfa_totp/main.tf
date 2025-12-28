# ==============================================================================
# TOTP MFA Strategy Module
# ==============================================================================
# Multi-Factor Authentication using Time-based One-Time Passwords (TOTP).
# Implements RFC 6238 (TOTP) and RFC 4226 (HOTP base algorithm).
#
# Security Features:
#   - TOTP secrets encrypted at rest via DynamoDB KMS
#   - Backup codes stored as SHA-256 hashes (single-use)
#   - Rate limiting on verification attempts
#   - SOC2-compliant audit logging
#
# Routes:
#   POST /auth/mfa/setup    -> Generate TOTP secret and QR code
#   POST /auth/mfa/verify   -> Verify TOTP code and enable MFA
#   POST /auth/mfa/validate -> Validate TOTP during login flow
#   POST /auth/mfa/disable  -> Disable MFA (requires current code)
#
# Build Process:
#   Terraform triggers npm build via null_resource when source files change.
#   Uses esbuild to bundle @oauth-server/shared into the Lambda package.
#   No manual build steps required - just run `make apply`.
# ==============================================================================

locals {
  setup_function_name    = "${var.project_name}-${var.environment}-auth-mfa-setup"
  verify_function_name   = "${var.project_name}-${var.environment}-auth-mfa-verify"
  validate_function_name = "${var.project_name}-${var.environment}-auth-mfa-validate"
  disable_function_name  = "${var.project_name}-${var.environment}-auth-mfa-disable"
  lambda_role_name       = "${var.project_name}-${var.environment}-auth-mfa-totp-role"
  source_dir             = "${path.module}/src"
  dist_dir               = "${path.module}/dist"
  totp_issuer            = var.totp_issuer != "" ? var.totp_issuer : var.brand_name != "" ? var.brand_name : var.project_name
}

# ==============================================================================
# CloudWatch Log Groups
# ==============================================================================

resource "aws_cloudwatch_log_group" "setup" {
  name              = "/aws/lambda/${local.setup_function_name}"
  retention_in_days = var.log_retention_days

  tags = {
    Name        = "${local.setup_function_name}-logs"
    Environment = var.environment
    Module      = "auth_mfa_totp"
  }
}

resource "aws_cloudwatch_log_group" "verify" {
  name              = "/aws/lambda/${local.verify_function_name}"
  retention_in_days = var.log_retention_days

  tags = {
    Name        = "${local.verify_function_name}-logs"
    Environment = var.environment
    Module      = "auth_mfa_totp"
  }
}

resource "aws_cloudwatch_log_group" "validate" {
  name              = "/aws/lambda/${local.validate_function_name}"
  retention_in_days = var.log_retention_days

  tags = {
    Name        = "${local.validate_function_name}-logs"
    Environment = var.environment
    Module      = "auth_mfa_totp"
  }
}

resource "aws_cloudwatch_log_group" "disable" {
  name              = "/aws/lambda/${local.disable_function_name}"
  retention_in_days = var.log_retention_days

  tags = {
    Name        = "${local.disable_function_name}-logs"
    Environment = var.environment
    Module      = "auth_mfa_totp"
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
    Module      = "auth_mfa_totp"
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
          "${aws_cloudwatch_log_group.setup.arn}:*",
          "${aws_cloudwatch_log_group.verify.arn}:*",
          "${aws_cloudwatch_log_group.validate.arn}:*",
          "${aws_cloudwatch_log_group.disable.arn}:*"
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
        Sid    = "GetUserAndMfaConfig"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem"
        ]
        Resource = var.dynamodb_table_arn
      },
      {
        Sid    = "UpdateUserMfaSettings"
        Effect = "Allow"
        Action = [
          "dynamodb:UpdateItem"
        ]
        Resource = var.dynamodb_table_arn
      },
      {
        Sid    = "WriteMfaSetupToken"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem"
        ]
        Resource = var.dynamodb_table_arn
      },
      {
        Sid    = "DeleteMfaSetupToken"
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
# KMS Policy (Encrypt/Decrypt for DynamoDB encryption)
# ------------------------------------------------------------------------------

resource "aws_iam_role_policy" "lambda_kms" {
  name = "${local.lambda_role_name}-kms"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBEncryption"
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
  output_path = "${path.module}/.terraform/auth-mfa-totp.zip"

  depends_on = [null_resource.build]
}

# ------------------------------------------------------------------------------
# Setup Handler Lambda
# POST /auth/mfa/setup
# ------------------------------------------------------------------------------

resource "aws_lambda_function" "setup" {
  function_name = local.setup_function_name
  role          = aws_iam_role.lambda_role.arn
  handler       = "setup.handler"
  runtime       = "nodejs20.x"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size

  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  environment {
    variables = {
      TABLE_NAME         = var.dynamodb_table_name
      TOTP_ISSUER        = local.totp_issuer
      TOTP_DIGITS        = tostring(var.totp_digits)
      TOTP_PERIOD        = tostring(var.totp_period)
      BACKUP_CODES_COUNT = tostring(var.backup_codes_count)
    }
  }

  tags = {
    Name        = local.setup_function_name
    Environment = var.environment
    Module      = "auth_mfa_totp"
  }

  depends_on = [
    aws_cloudwatch_log_group.setup,
    aws_iam_role_policy.lambda_logs,
    aws_iam_role_policy.lambda_dynamodb,
    aws_iam_role_policy.lambda_kms,
    null_resource.build,
  ]
}

# ------------------------------------------------------------------------------
# Verify Handler Lambda
# POST /auth/mfa/verify
# ------------------------------------------------------------------------------

resource "aws_lambda_function" "verify" {
  function_name = local.verify_function_name
  role          = aws_iam_role.lambda_role.arn
  handler       = "verify.handler"
  runtime       = "nodejs20.x"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size

  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  environment {
    variables = {
      TABLE_NAME  = var.dynamodb_table_name
      TOTP_DIGITS = tostring(var.totp_digits)
      TOTP_PERIOD = tostring(var.totp_period)
      TOTP_WINDOW = tostring(var.totp_window)
    }
  }

  tags = {
    Name        = local.verify_function_name
    Environment = var.environment
    Module      = "auth_mfa_totp"
  }

  depends_on = [
    aws_cloudwatch_log_group.verify,
    aws_iam_role_policy.lambda_logs,
    aws_iam_role_policy.lambda_dynamodb,
    aws_iam_role_policy.lambda_kms,
    null_resource.build,
  ]
}

# ------------------------------------------------------------------------------
# Validate Handler Lambda
# POST /auth/mfa/validate
# ------------------------------------------------------------------------------

resource "aws_lambda_function" "validate" {
  function_name = local.validate_function_name
  role          = aws_iam_role.lambda_role.arn
  handler       = "validate.handler"
  runtime       = "nodejs20.x"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size

  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  environment {
    variables = {
      TABLE_NAME  = var.dynamodb_table_name
      TOTP_DIGITS = tostring(var.totp_digits)
      TOTP_PERIOD = tostring(var.totp_period)
      TOTP_WINDOW = tostring(var.totp_window)
    }
  }

  tags = {
    Name        = local.validate_function_name
    Environment = var.environment
    Module      = "auth_mfa_totp"
  }

  depends_on = [
    aws_cloudwatch_log_group.validate,
    aws_iam_role_policy.lambda_logs,
    aws_iam_role_policy.lambda_dynamodb,
    aws_iam_role_policy.lambda_kms,
    null_resource.build,
  ]
}

# ------------------------------------------------------------------------------
# Disable Handler Lambda
# POST /auth/mfa/disable
# ------------------------------------------------------------------------------

resource "aws_lambda_function" "disable" {
  function_name = local.disable_function_name
  role          = aws_iam_role.lambda_role.arn
  handler       = "disable.handler"
  runtime       = "nodejs20.x"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size

  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  environment {
    variables = {
      TABLE_NAME  = var.dynamodb_table_name
      TOTP_DIGITS = tostring(var.totp_digits)
      TOTP_PERIOD = tostring(var.totp_period)
      TOTP_WINDOW = tostring(var.totp_window)
    }
  }

  tags = {
    Name        = local.disable_function_name
    Environment = var.environment
    Module      = "auth_mfa_totp"
  }

  depends_on = [
    aws_cloudwatch_log_group.disable,
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
# Setup Route: POST /auth/mfa/setup
# ------------------------------------------------------------------------------

resource "aws_apigatewayv2_integration" "setup" {
  api_id                 = var.api_gateway_id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.setup.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "setup" {
  api_id    = var.api_gateway_id
  route_key = "POST /auth/mfa/setup"
  target    = "integrations/${aws_apigatewayv2_integration.setup.id}"
}

resource "aws_lambda_permission" "setup_api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.setup.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${var.api_gateway_execution_arn}/*/*"
}

# ------------------------------------------------------------------------------
# Verify Route: POST /auth/mfa/verify
# ------------------------------------------------------------------------------

resource "aws_apigatewayv2_integration" "verify" {
  api_id                 = var.api_gateway_id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.verify.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "verify" {
  api_id    = var.api_gateway_id
  route_key = "POST /auth/mfa/verify"
  target    = "integrations/${aws_apigatewayv2_integration.verify.id}"
}

resource "aws_lambda_permission" "verify_api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.verify.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${var.api_gateway_execution_arn}/*/*"
}

# ------------------------------------------------------------------------------
# Validate Route: POST /auth/mfa/validate
# ------------------------------------------------------------------------------

resource "aws_apigatewayv2_integration" "validate" {
  api_id                 = var.api_gateway_id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.validate.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "validate" {
  api_id    = var.api_gateway_id
  route_key = "POST /auth/mfa/validate"
  target    = "integrations/${aws_apigatewayv2_integration.validate.id}"
}

resource "aws_lambda_permission" "validate_api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.validate.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${var.api_gateway_execution_arn}/*/*"
}

# ------------------------------------------------------------------------------
# Disable Route: POST /auth/mfa/disable
# ------------------------------------------------------------------------------

resource "aws_apigatewayv2_integration" "disable" {
  api_id                 = var.api_gateway_id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.disable.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "disable" {
  api_id    = var.api_gateway_id
  route_key = "POST /auth/mfa/disable"
  target    = "integrations/${aws_apigatewayv2_integration.disable.id}"
}

resource "aws_lambda_permission" "disable_api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.disable.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${var.api_gateway_execution_arn}/*/*"
}
