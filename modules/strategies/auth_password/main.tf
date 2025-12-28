# ==============================================================================
# OAuth Server - Password Authentication Strategy
# ==============================================================================
# Pluggable authentication strategy for email/password login.
# Implements the AuthStrategy interface from the protocol layer.
#
# Security Features:
#   - Argon2id password hashing (memory-hard, GPU-resistant)
#   - CSRF protection with HMAC-SHA256 tokens
#   - Brute force protection with configurable lockout
#   - Password reset via secure email tokens
#   - SOC2-compliant audit logging
#
# Routes:
#   GET  /auth/password/login   -> Render login form
#   POST /auth/password/verify  -> Validate credentials
#   POST /auth/password/forgot  -> Request password reset email
#   POST /auth/password/reset   -> Reset password with token
#
# Build Process:
#   Terraform triggers npm build via null_resource when source files change.
#   Uses esbuild to bundle @oauth-server/shared into the Lambda package.
#   No manual build steps required - just run `make apply`.
# ==============================================================================

locals {
  login_function_name  = "${var.project_name}-${var.environment}-auth-password-login"
  verify_function_name = "${var.project_name}-${var.environment}-auth-password-verify"
  forgot_function_name = "${var.project_name}-${var.environment}-auth-password-forgot"
  reset_function_name  = "${var.project_name}-${var.environment}-auth-password-reset"
  lambda_role_name     = "${var.project_name}-${var.environment}-auth-password-role"
  source_dir           = "${path.module}/src"
  dist_dir             = "${path.module}/dist"
}

# ==============================================================================
# CloudWatch Log Groups
# ==============================================================================

resource "aws_cloudwatch_log_group" "login" {
  name              = "/aws/lambda/${local.login_function_name}"
  retention_in_days = var.log_retention_days

  tags = {
    Name        = "${local.login_function_name}-logs"
    Environment = var.environment
    Module      = "auth_password"
  }
}

resource "aws_cloudwatch_log_group" "verify" {
  name              = "/aws/lambda/${local.verify_function_name}"
  retention_in_days = var.log_retention_days

  tags = {
    Name        = "${local.verify_function_name}-logs"
    Environment = var.environment
    Module      = "auth_password"
  }
}

resource "aws_cloudwatch_log_group" "forgot" {
  name              = "/aws/lambda/${local.forgot_function_name}"
  retention_in_days = var.log_retention_days

  tags = {
    Name        = "${local.forgot_function_name}-logs"
    Environment = var.environment
    Module      = "auth_password"
  }
}

resource "aws_cloudwatch_log_group" "reset" {
  name              = "/aws/lambda/${local.reset_function_name}"
  retention_in_days = var.log_retention_days

  tags = {
    Name        = "${local.reset_function_name}-logs"
    Environment = var.environment
    Module      = "auth_password"
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
    Module      = "auth_password"
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
          "${aws_cloudwatch_log_group.login.arn}:*",
          "${aws_cloudwatch_log_group.verify.arn}:*",
          "${aws_cloudwatch_log_group.forgot.arn}:*",
          "${aws_cloudwatch_log_group.reset.arn}:*"
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
        Sid    = "GetSessionAndUser"
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
        Sid    = "UpdateSessionAndUser"
        Effect = "Allow"
        Action = [
          "dynamodb:UpdateItem"
        ]
        Resource = var.dynamodb_table_arn
      },
      {
        Sid    = "WritePasswordResetToken"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem"
        ]
        Resource = var.dynamodb_table_arn
      },
      {
        Sid    = "DeletePasswordResetToken"
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

# ------------------------------------------------------------------------------
# SES Policy (Send templated emails for password reset)
# ------------------------------------------------------------------------------

resource "aws_iam_role_policy" "lambda_ses" {
  count = var.ses_sender_email != "" ? 1 : 0
  name  = "${local.lambda_role_name}-ses"
  role  = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SendTemplatedEmail"
        Effect = "Allow"
        Action = [
          "ses:SendTemplatedEmail"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "ses:FromAddress" = var.ses_sender_email
          }
        }
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
# ARGON2 IMPLEMENTATION:
# Uses hash-wasm which is a pure WebAssembly implementation.
# No native binaries - works on any platform without compilation.
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

    # Rebuild when templates change (login)
    templates_hash = sha256(join("", [
      filesha256("${path.module}/../../../templates/login/index.html"),
      fileexists("${path.module}/../../../templates/login/styles.css") ? filesha256("${path.module}/../../../templates/login/styles.css") : "",
    ]))

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
  output_path = "${path.module}/.terraform/auth-password.zip"

  depends_on = [null_resource.build]
}

# ------------------------------------------------------------------------------
# Login Handler Lambda
# GET /auth/password/login
# ------------------------------------------------------------------------------

resource "aws_lambda_function" "login" {
  function_name = local.login_function_name
  role          = aws_iam_role.lambda_role.arn
  handler       = "login-handler.handler"
  runtime       = "nodejs20.x"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size

  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  environment {
    variables = {
      TABLE_NAME  = var.dynamodb_table_name
      CSRF_SECRET = var.csrf_secret
      VERIFY_URL  = "/auth/password/verify"
      BRAND_NAME  = var.brand_name != "" ? var.brand_name : var.project_name
    }
  }

  tags = {
    Name        = local.login_function_name
    Environment = var.environment
    Module      = "auth_password"
  }

  depends_on = [
    aws_cloudwatch_log_group.login,
    aws_iam_role_policy.lambda_logs,
    aws_iam_role_policy.lambda_dynamodb,
    aws_iam_role_policy.lambda_kms,
    null_resource.build,
  ]
}

# ------------------------------------------------------------------------------
# Verify Handler Lambda
# POST /auth/password/verify
# ------------------------------------------------------------------------------

resource "aws_lambda_function" "verify" {
  function_name = local.verify_function_name
  role          = aws_iam_role.lambda_role.arn
  handler       = "verify-handler.handler"
  runtime       = "nodejs20.x"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size

  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  environment {
    variables = {
      TABLE_NAME               = var.dynamodb_table_name
      CSRF_SECRET              = var.csrf_secret
      LOGIN_URL                = "/auth/password/login"
      CALLBACK_URL             = var.protocol_callback_url
      MAX_FAILED_ATTEMPTS      = tostring(var.max_failed_login_attempts)
      LOCKOUT_DURATION_SECONDS = tostring(var.lockout_duration_seconds)
      MFA_VALIDATE_URL         = var.mfa_validate_url
    }
  }

  tags = {
    Name        = local.verify_function_name
    Environment = var.environment
    Module      = "auth_password"
  }

  depends_on = [
    aws_cloudwatch_log_group.verify,
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
# Login Route: GET /auth/password/login
# ------------------------------------------------------------------------------

resource "aws_apigatewayv2_integration" "login" {
  api_id                 = var.api_gateway_id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.login.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "login" {
  api_id    = var.api_gateway_id
  route_key = "GET /auth/password/login"
  target    = "integrations/${aws_apigatewayv2_integration.login.id}"
}

resource "aws_lambda_permission" "login_api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.login.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${var.api_gateway_execution_arn}/*/*"
}

# ------------------------------------------------------------------------------
# Verify Route: POST /auth/password/verify
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
  route_key = "POST /auth/password/verify"
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
# Forgot Password Handler Lambda
# POST /auth/password/forgot
# ------------------------------------------------------------------------------

resource "aws_lambda_function" "forgot" {
  count         = var.ses_sender_email != "" ? 1 : 0
  function_name = local.forgot_function_name
  role          = aws_iam_role.lambda_role.arn
  handler       = "forgot-handler.handler"
  runtime       = "nodejs20.x"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size

  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  environment {
    variables = {
      TABLE_NAME              = var.dynamodb_table_name
      RESET_TOKEN_TTL         = tostring(var.password_reset_token_ttl)
      RESET_PAGE_URL          = var.password_reset_page_url
      SES_SENDER_EMAIL        = var.ses_sender_email
      SES_SENDER_NAME         = var.ses_sender_name != "" ? var.ses_sender_name : var.brand_name != "" ? var.brand_name : var.project_name
      SES_CONFIGURATION_SET   = var.ses_configuration_set
      PASSWORD_RESET_TEMPLATE = var.password_reset_template_name
    }
  }

  tags = {
    Name        = local.forgot_function_name
    Environment = var.environment
    Module      = "auth_password"
  }

  depends_on = [
    aws_cloudwatch_log_group.forgot,
    aws_iam_role_policy.lambda_logs,
    aws_iam_role_policy.lambda_dynamodb,
    aws_iam_role_policy.lambda_kms,
    aws_iam_role_policy.lambda_ses,
    null_resource.build,
  ]
}

# ------------------------------------------------------------------------------
# Reset Password Handler Lambda
# POST /auth/password/reset
# ------------------------------------------------------------------------------

resource "aws_lambda_function" "reset" {
  count         = var.ses_sender_email != "" ? 1 : 0
  function_name = local.reset_function_name
  role          = aws_iam_role.lambda_role.arn
  handler       = "reset-handler.handler"
  runtime       = "nodejs20.x"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size

  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  environment {
    variables = {
      TABLE_NAME                 = var.dynamodb_table_name
      PASSWORD_MIN_LENGTH        = tostring(var.password_min_length)
      PASSWORD_REQUIRE_UPPERCASE = var.password_require_uppercase ? "true" : "false"
      PASSWORD_REQUIRE_LOWERCASE = var.password_require_lowercase ? "true" : "false"
      PASSWORD_REQUIRE_NUMBER    = var.password_require_number ? "true" : "false"
      PASSWORD_REQUIRE_SPECIAL   = var.password_require_special ? "true" : "false"
    }
  }

  tags = {
    Name        = local.reset_function_name
    Environment = var.environment
    Module      = "auth_password"
  }

  depends_on = [
    aws_cloudwatch_log_group.reset,
    aws_iam_role_policy.lambda_logs,
    aws_iam_role_policy.lambda_dynamodb,
    aws_iam_role_policy.lambda_kms,
    null_resource.build,
  ]
}

# ------------------------------------------------------------------------------
# Forgot Password Route: POST /auth/password/forgot
# ------------------------------------------------------------------------------

resource "aws_apigatewayv2_integration" "forgot" {
  count                  = var.ses_sender_email != "" ? 1 : 0
  api_id                 = var.api_gateway_id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.forgot[0].invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "forgot" {
  count     = var.ses_sender_email != "" ? 1 : 0
  api_id    = var.api_gateway_id
  route_key = "POST /auth/password/forgot"
  target    = "integrations/${aws_apigatewayv2_integration.forgot[0].id}"
}

resource "aws_lambda_permission" "forgot_api_gateway" {
  count         = var.ses_sender_email != "" ? 1 : 0
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.forgot[0].function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${var.api_gateway_execution_arn}/*/*"
}

# ------------------------------------------------------------------------------
# Reset Password Route: POST /auth/password/reset
# ------------------------------------------------------------------------------

resource "aws_apigatewayv2_integration" "reset" {
  count                  = var.ses_sender_email != "" ? 1 : 0
  api_id                 = var.api_gateway_id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.reset[0].invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "reset" {
  count     = var.ses_sender_email != "" ? 1 : 0
  api_id    = var.api_gateway_id
  route_key = "POST /auth/password/reset"
  target    = "integrations/${aws_apigatewayv2_integration.reset[0].id}"
}

resource "aws_lambda_permission" "reset_api_gateway" {
  count         = var.ses_sender_email != "" ? 1 : 0
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.reset[0].function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${var.api_gateway_execution_arn}/*/*"
}
