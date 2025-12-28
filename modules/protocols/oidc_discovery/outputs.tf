# ==============================================================================
# OIDC Discovery Endpoint - Outputs
# ==============================================================================

output "discovery_function_name" {
  description = "Name of the discovery Lambda function"
  value       = aws_lambda_function.discovery.function_name
}

output "jwks_function_name" {
  description = "Name of the JWKS Lambda function"
  value       = aws_lambda_function.jwks.function_name
}

output "discovery_function_arn" {
  description = "ARN of the discovery Lambda function"
  value       = aws_lambda_function.discovery.arn
}

output "jwks_function_arn" {
  description = "ARN of the JWKS Lambda function"
  value       = aws_lambda_function.jwks.arn
}

output "role_arn" {
  description = "IAM role ARN used by the Lambda functions"
  value       = aws_iam_role.lambda_role.arn
}
