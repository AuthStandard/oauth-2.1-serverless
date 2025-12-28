# ==============================================================================
# TOTP MFA Strategy Module - Outputs
# ==============================================================================

output "setup_function_name" {
  description = "Name of the MFA setup Lambda function"
  value       = aws_lambda_function.setup.function_name
}

output "verify_function_name" {
  description = "Name of the MFA verify Lambda function"
  value       = aws_lambda_function.verify.function_name
}

output "validate_function_name" {
  description = "Name of the MFA validate Lambda function"
  value       = aws_lambda_function.validate.function_name
}

output "disable_function_name" {
  description = "Name of the MFA disable Lambda function"
  value       = aws_lambda_function.disable.function_name
}

output "setup_invoke_arn" {
  description = "Invoke ARN for the MFA setup Lambda function"
  value       = aws_lambda_function.setup.invoke_arn
}

output "validate_invoke_arn" {
  description = "Invoke ARN for the MFA validate Lambda function"
  value       = aws_lambda_function.validate.invoke_arn
}
