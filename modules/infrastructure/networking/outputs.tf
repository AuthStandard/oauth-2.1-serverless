# ==============================================================================
# Networking Module - Outputs
# ==============================================================================
# These outputs are consumed by protocol and strategy modules for:
#   - Lambda integrations (api_gateway_id, api_gateway_execution_arn)
#   - Environment configuration (api_endpoint)
#   - Monitoring and debugging (log_group_arn, stage_id)
#
# OAuth 2.1 Compliance (Section 1.5 - Communication Security):
#   - api_endpoint serves as the issuer URL if no custom domain is configured
#   - All endpoints are HTTPS (API Gateway enforces TLS 1.2+)
#   - Issuer identifier MUST be a URL using the https scheme
# ==============================================================================

output "api_gateway_id" {
  description = "API Gateway ID for route attachments via aws_apigatewayv2_route"
  value       = aws_apigatewayv2_api.main.id
}

output "api_gateway_execution_arn" {
  description = "API Gateway execution ARN for Lambda invoke permissions"
  value       = aws_apigatewayv2_api.main.execution_arn
}

output "api_endpoint" {
  description = "API Gateway base URL (used as issuer if no custom domain). Always HTTPS per OAuth 2.1 Section 1.5."
  value       = aws_apigatewayv2_api.main.api_endpoint
}

output "api_gateway_arn" {
  description = "API Gateway ARN for IAM policies and resource tagging"
  value       = aws_apigatewayv2_api.main.arn
}

output "stage_id" {
  description = "Default stage ID for stage-specific configurations"
  value       = aws_apigatewayv2_stage.default.id
}

output "stage_name" {
  description = "Default stage name"
  value       = aws_apigatewayv2_stage.default.name
}

output "stage_invoke_url" {
  description = "Stage invoke URL for direct API calls"
  value       = aws_apigatewayv2_stage.default.invoke_url
}

output "log_group_arn" {
  description = "API Gateway access log group ARN for monitoring dashboards"
  value       = aws_cloudwatch_log_group.api_gateway.arn
}

output "log_group_name" {
  description = "API Gateway access log group name for CloudWatch queries"
  value       = aws_cloudwatch_log_group.api_gateway.name
}

# ==============================================================================
# Throttling Configuration Outputs
# ==============================================================================
# Expose throttling settings for monitoring dashboards and environment tuning.
# These values can be adjusted per environment (lower for dev, higher for prod).
# ==============================================================================

output "throttling_burst_limit" {
  description = "Configured API Gateway throttling burst limit (maximum concurrent requests)"
  value       = var.throttling_burst_limit
}

output "throttling_rate_limit" {
  description = "Configured API Gateway throttling rate limit (requests per second)"
  value       = var.throttling_rate_limit
}
