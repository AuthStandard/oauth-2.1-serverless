# ==============================================================================
# OAuth 2.1 Token Endpoint - Outputs
# ==============================================================================

output "function_name" {
  description = "Lambda function name"
  value       = aws_lambda_function.token.function_name
}

output "function_arn" {
  description = "Lambda function ARN"
  value       = aws_lambda_function.token.arn
}

output "invoke_arn" {
  description = "Lambda function invoke ARN for API Gateway"
  value       = aws_lambda_function.token.invoke_arn
}

output "role_arn" {
  description = "IAM role ARN used by the Lambda function"
  value       = aws_iam_role.lambda_role.arn
}

output "log_group_name" {
  description = "CloudWatch log group name for Lambda logs"
  value       = aws_cloudwatch_log_group.lambda.name
}

output "log_group_arn" {
  description = "CloudWatch log group ARN"
  value       = aws_cloudwatch_log_group.lambda.arn
}
