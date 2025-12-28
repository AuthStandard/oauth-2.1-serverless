# ==============================================================================
# SAML Authentication Strategy - Outputs
# ==============================================================================

output "metadata_function_name" {
  description = "Name of the SP metadata Lambda function"
  value       = aws_lambda_function.metadata.function_name
}

output "metadata_function_arn" {
  description = "ARN of the SP metadata Lambda function"
  value       = aws_lambda_function.metadata.arn
}

output "callback_function_name" {
  description = "Name of the SAML callback Lambda function"
  value       = aws_lambda_function.callback.function_name
}

output "callback_function_arn" {
  description = "ARN of the SAML callback Lambda function"
  value       = aws_lambda_function.callback.arn
}

output "metadata_route" {
  description = "API Gateway route for SP metadata"
  value       = aws_apigatewayv2_route.metadata.route_key
}

output "callback_route" {
  description = "API Gateway route for SAML callback"
  value       = aws_apigatewayv2_route.callback.route_key
}
