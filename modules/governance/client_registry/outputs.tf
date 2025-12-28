# ==============================================================================
# RFC 7591/7592 Client Registry - Outputs
# ==============================================================================

output "lambda_function_name" {
  description = "Name of the Client Registry Lambda function"
  value       = aws_lambda_function.client_registry.function_name
}

output "lambda_function_arn" {
  description = "ARN of the Client Registry Lambda function"
  value       = aws_lambda_function.client_registry.arn
}

output "lambda_invoke_arn" {
  description = "Invoke ARN of the Client Registry Lambda function"
  value       = aws_lambda_function.client_registry.invoke_arn
}

output "log_group_name" {
  description = "CloudWatch Log Group name for the Lambda function"
  value       = aws_cloudwatch_log_group.lambda.name
}

output "log_group_arn" {
  description = "CloudWatch Log Group ARN for the Lambda function"
  value       = aws_cloudwatch_log_group.lambda.arn
}

output "registration_endpoint" {
  description = "Client registration endpoint URL (POST to create, GET/PUT/DELETE with clientId)"
  value       = "/connect/register"
}
