# ==============================================================================
# Password Authentication Strategy - Outputs
# ==============================================================================

output "login_function_name" {
  description = "Name of the login Lambda function"
  value       = aws_lambda_function.login.function_name
}

output "verify_function_name" {
  description = "Name of the verify Lambda function"
  value       = aws_lambda_function.verify.function_name
}

output "login_function_arn" {
  description = "ARN of the login Lambda function"
  value       = aws_lambda_function.login.arn
}

output "verify_function_arn" {
  description = "ARN of the verify Lambda function"
  value       = aws_lambda_function.verify.arn
}

output "login_route_key" {
  description = "API Gateway route key for the login endpoint"
  value       = aws_apigatewayv2_route.login.route_key
}

output "verify_route_key" {
  description = "API Gateway route key for the verify endpoint"
  value       = aws_apigatewayv2_route.verify.route_key
}
