# ==============================================================================
# Notifications Infrastructure Module - Outputs
# ==============================================================================

output "password_reset_template_name" {
  description = "Name of the SES password reset email template"
  value       = aws_ses_template.password_reset.name
}

output "email_verification_template_name" {
  description = "Name of the SES email verification template"
  value       = aws_ses_template.email_verification.name
}

output "sender_email" {
  description = "Configured sender email address"
  value       = var.ses_sender_email
}

output "sender_name" {
  description = "Configured sender display name"
  value       = local.brand_name
}

output "password_reset_token_ttl" {
  description = "Password reset token TTL in seconds"
  value       = var.password_reset_token_ttl
}

output "email_verification_token_ttl" {
  description = "Email verification token TTL in seconds"
  value       = var.email_verification_token_ttl
}
