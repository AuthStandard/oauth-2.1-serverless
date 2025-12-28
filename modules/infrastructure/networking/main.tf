# ==============================================================================
# Networking Module
# ==============================================================================
# Shared API Gateway V2 (HTTP API) for all OAuth 2.1 endpoints.
#
# ARCHITECTURE
# ------------
# - Protocol: HTTP API (v2) - lower latency and cost vs REST API
# - Deployment: Auto-deploy stage for immediate route updates
# - Logging: Structured JSON access logs for SOC2 audit compliance
# - Protection: Configurable throttling for DDoS mitigation
#
# ROUTE REGISTRATION
# ------------------
# Protocol and strategy modules attach routes to this gateway using:
#   - aws_apigatewayv2_integration (Lambda proxy integration)
#   - aws_apigatewayv2_route (HTTP method + path binding)
#
# OAUTH 2.1 ENDPOINTS (draft-ietf-oauth-v2-1-14)
# ----------------------------------------------
# | Endpoint                              | Method | Module           |
# |---------------------------------------|--------|------------------|
# | /authorize                            | GET    | oauth2_authorize |
# | /authorize/callback                   | GET    | oauth2_authorize |
# | /token                                | POST   | oauth2_token     |
# | /.well-known/openid-configuration     | GET    | oidc_discovery   |
# | /keys                                 | GET    | oidc_discovery   |
#
# CORS CONFIGURATION (OAuth 2.1 Section 1.5, Browser-Based Apps BCP)
# ------------------------------------------------------------------
# - Authorization endpoint (/authorize): No CORS needed - browser navigation
# - Token endpoint (/token): CORS required for SPA public clients
# - Access-Control-Allow-Credentials: FALSE for public clients
#   (PKCE clients authenticate via code_verifier, not cookies/sessions)
# - Wildcard origins (*): Explicitly blocked for security
#   (OAuth 2.1 requires explicit redirect_uri matching)
#
# SECURITY HEADERS (SOC2 Compliance)
# ----------------------------------
# HTTP API Gateway v2 does NOT support response header manipulation at the
# gateway level (unlike REST API). Security headers are enforced at the
# Lambda response level via @oauth-server/shared response helpers:
#
#   - Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
#   - X-Content-Type-Options: nosniff
#   - X-Frame-Options: DENY
#   - Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
#   - Cache-Control: no-store (OAuth 2.1 requirement)
#
# All Lambda functions MUST use the shared response helpers to ensure
# consistent security header enforcement across all endpoints.
#
# SECURITY (OAuth 2.1 Section 1.5 - Communication Security)
# ---------------------------------------------------------
# - TLS 1.2+ enforced by API Gateway (no configuration needed)
# - All OAuth endpoints MUST use HTTPS (enforced by API Gateway)
# - Throttling prevents abuse and ensures fair usage
# - Access logs capture all requests for security audit trail
# - X-Request-Id exposed for distributed tracing correlation
#
# REFERENCES
# ----------
# - OAuth 2.1: draft-ietf-oauth-v2-1-14 Section 1.5 (Communication Security)
# - Browser-Based Apps: draft-ietf-oauth-browser-based-apps
# - RFC 6454: The Web Origin Concept
# - RFC 6797: HTTP Strict Transport Security (HSTS)
# ==============================================================================

locals {
  gateway_name = "${var.project_name}-${var.environment}-api"
}

# ==============================================================================
# API Gateway Access Log Group
# ==============================================================================

resource "aws_cloudwatch_log_group" "api_gateway" {
  name              = "/aws/api-gateway/${var.project_name}-${var.environment}"
  retention_in_days = var.log_retention_days

  tags = {
    Name        = "${var.project_name}-${var.environment}-api-gateway-logs"
    Environment = var.environment
    Module      = "networking"
  }
}

# ==============================================================================
# HTTP API Gateway
# ==============================================================================

resource "aws_apigatewayv2_api" "main" {
  name          = local.gateway_name
  protocol_type = "HTTP"
  description   = "OAuth 2.1 Authorization Server API (${var.environment})"

  cors_configuration {
    allow_origins     = var.cors_allowed_origins
    allow_methods     = ["GET", "POST", "OPTIONS"]
    allow_headers     = ["Content-Type", "Authorization", "X-Requested-With", "Accept", "DPoP"]
    expose_headers    = ["X-Request-Id", "WWW-Authenticate", "DPoP-Nonce"]
    allow_credentials = var.cors_allow_credentials
    max_age           = var.cors_max_age
  }

  tags = {
    Name        = local.gateway_name
    Environment = var.environment
    Module      = "networking"
  }
}

# ==============================================================================
# Default Stage with Auto-Deploy
# ==============================================================================

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.main.id
  name        = "$default"
  auto_deploy = true

  # SOC2-compliant structured access logging
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gateway.arn
    format = jsonencode({
      requestId          = "$context.requestId"
      extendedRequestId  = "$context.extendedRequestId"
      sourceIp           = "$context.identity.sourceIp"
      requestTime        = "$context.requestTime"
      requestTimeEpoch   = "$context.requestTimeEpoch"
      httpMethod         = "$context.httpMethod"
      routeKey           = "$context.routeKey"
      path               = "$context.path"
      status             = "$context.status"
      protocol           = "$context.protocol"
      responseLength     = "$context.responseLength"
      responseLatency    = "$context.responseLatency"
      integrationLatency = "$context.integrationLatency"
      integrationStatus  = "$context.integrationStatus"
      errorMessage       = "$context.error.message"
      errorResponseType  = "$context.error.responseType"
      userAgent          = "$context.identity.userAgent"
    })
  }

  default_route_settings {
    throttling_burst_limit = var.throttling_burst_limit
    throttling_rate_limit  = var.throttling_rate_limit
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-default-stage"
    Environment = var.environment
    Module      = "networking"
  }
}
