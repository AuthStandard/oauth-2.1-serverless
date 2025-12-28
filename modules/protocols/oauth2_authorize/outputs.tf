# ==============================================================================
# OAuth 2.1 Authorization Endpoint - Outputs
# ==============================================================================

output "authorize_function_name" {
  description = "Authorize Lambda function name"
  value       = aws_lambda_function.authorize.function_name
}

output "authorize_function_arn" {
  description = "Authorize Lambda function ARN"
  value       = aws_lambda_function.authorize.arn
}

output "authorize_invoke_arn" {
  description = "Authorize Lambda function invoke ARN for API Gateway"
  value       = aws_lambda_function.authorize.invoke_arn
}

output "callback_function_name" {
  description = "Callback Lambda function name"
  value       = aws_lambda_function.callback.function_name
}

output "callback_function_arn" {
  description = "Callback Lambda function ARN"
  value       = aws_lambda_function.callback.arn
}

output "callback_invoke_arn" {
  description = "Callback Lambda function invoke ARN for API Gateway"
  value       = aws_lambda_function.callback.invoke_arn
}

output "role_arn" {
  description = "IAM role ARN used by the Lambda functions"
  value       = aws_iam_role.lambda_role.arn
}

output "authorize_log_group_name" {
  description = "CloudWatch log group name for authorize Lambda logs"
  value       = aws_cloudwatch_log_group.authorize.name
}

output "authorize_log_group_arn" {
  description = "CloudWatch log group ARN for authorize Lambda"
  value       = aws_cloudwatch_log_group.authorize.arn
}

output "callback_log_group_name" {
  description = "CloudWatch log group name for callback Lambda logs"
  value       = aws_cloudwatch_log_group.callback.name
}

output "callback_log_group_arn" {
  description = "CloudWatch log group ARN for callback Lambda"
  value       = aws_cloudwatch_log_group.callback.arn
}
