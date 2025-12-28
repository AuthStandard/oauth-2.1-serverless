# ==============================================================================
# SCIM v2 Group Provisioning Module - Outputs
# ==============================================================================

output "lambda_function_name" {
  description = "Name of the SCIM Groups Lambda function"
  value       = aws_lambda_function.scim_groups.function_name
}

output "lambda_function_arn" {
  description = "ARN of the SCIM Groups Lambda function"
  value       = aws_lambda_function.scim_groups.arn
}

output "lambda_role_arn" {
  description = "ARN of the Lambda execution role"
  value       = aws_iam_role.lambda_role.arn
}

output "log_group_name" {
  description = "CloudWatch log group name"
  value       = aws_cloudwatch_log_group.lambda.name
}
