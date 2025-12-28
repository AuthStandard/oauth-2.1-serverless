# ==============================================================================
# SCIM v2 User Provisioning Module - Outputs
# ==============================================================================

output "lambda_function_name" {
  description = "Name of the SCIM Users Lambda function"
  value       = aws_lambda_function.scim_users.function_name
}

output "lambda_function_arn" {
  description = "ARN of the SCIM Users Lambda function"
  value       = aws_lambda_function.scim_users.arn
}

output "lambda_role_arn" {
  description = "ARN of the Lambda execution role"
  value       = aws_iam_role.lambda_role.arn
}

output "log_group_name" {
  description = "CloudWatch log group name"
  value       = aws_cloudwatch_log_group.lambda.name
}
