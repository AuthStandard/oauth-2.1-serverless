# ==============================================================================
# OIDC UserInfo Endpoint - Outputs
# ==============================================================================

output "function_name" {
  description = "Name of the Lambda function"
  value       = aws_lambda_function.userinfo.function_name
}

output "function_arn" {
  description = "ARN of the Lambda function"
  value       = aws_lambda_function.userinfo.arn
}

output "invoke_arn" {
  description = "Invoke ARN of the Lambda function"
  value       = aws_lambda_function.userinfo.invoke_arn
}

output "role_arn" {
  description = "IAM role ARN used by the Lambda function"
  value       = aws_iam_role.lambda_role.arn
}

output "log_group_name" {
  description = "CloudWatch Log Group name"
  value       = aws_cloudwatch_log_group.lambda.name
}
