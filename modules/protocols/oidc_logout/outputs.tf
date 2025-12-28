# ==============================================================================
# OIDC RP-Initiated Logout Endpoint - Outputs
# ==============================================================================

output "function_name" {
  description = "Name of the Lambda function"
  value       = aws_lambda_function.logout.function_name
}

output "function_arn" {
  description = "ARN of the Lambda function"
  value       = aws_lambda_function.logout.arn
}

output "invoke_arn" {
  description = "Invoke ARN of the Lambda function"
  value       = aws_lambda_function.logout.invoke_arn
}

output "role_arn" {
  description = "IAM role ARN used by the Lambda function"
  value       = aws_iam_role.lambda_role.arn
}

output "log_group_name" {
  description = "CloudWatch Log Group name"
  value       = aws_cloudwatch_log_group.lambda.name
}

output "log_group_arn" {
  description = "CloudWatch Log Group ARN"
  value       = aws_cloudwatch_log_group.lambda.arn
}

output "endpoint_path" {
  description = "API Gateway route path for the logout endpoint"
  value       = "/connect/logout"
}
