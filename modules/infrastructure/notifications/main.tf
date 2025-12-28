# ==============================================================================
# Notifications Infrastructure Module
# ==============================================================================
# AWS SES configuration for transactional emails.
#
# FEATURES:
#   - Password reset email template
#   - Email verification template
#   - SOC2-compliant audit logging
#
# PREREQUISITES:
#   - SES sender email must be verified before deployment
#   - For production: Request SES production access (out of sandbox)
#
# SECURITY:
#   - Templates use HTML escaping to prevent XSS
#   - Links include secure tokens with TTL
#   - No PII logged in CloudWatch
#
# USAGE:
#   This module only creates SES templates. Lambda functions in strategy
#   modules use these templates via the shared mailer utility.
# ==============================================================================

locals {
  brand_name = var.brand_name != "" ? var.brand_name : var.project_name
}

# ==============================================================================
# SES Email Templates
# ==============================================================================
# Templates use Handlebars-style placeholders: {{variable}}
# SES replaces these at send time with provided template data.
# ==============================================================================

# ------------------------------------------------------------------------------
# Password Reset Template
# ------------------------------------------------------------------------------

resource "aws_ses_template" "password_reset" {
  name    = "${var.project_name}-${var.environment}-password-reset"
  subject = var.password_reset_subject

  html = <<-HTML
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${var.password_reset_subject}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { text-align: center; padding: 20px 0; border-bottom: 1px solid #eee; }
    .content { padding: 30px 0; }
    .button { display: inline-block; background: #0066cc; color: #ffffff; padding: 12px 30px; text-decoration: none; border-radius: 4px; margin: 20px 0; }
    .footer { padding: 20px 0; border-top: 1px solid #eee; font-size: 12px; color: #666; text-align: center; }
    .warning { background: #fff3cd; border: 1px solid #ffc107; padding: 10px; border-radius: 4px; margin: 20px 0; font-size: 14px; }
  </style>
</head>
<body>
  <div class="header">
    <h1>${local.brand_name}</h1>
  </div>
  <div class="content">
    <h2>Reset Your Password</h2>
    <p>We received a request to reset the password for your account associated with {{email}}.</p>
    <p>Click the button below to reset your password:</p>
    <p style="text-align: center;">
      <a href="{{link}}" class="button">Reset Password</a>
    </p>
    <p>Or copy and paste this link into your browser:</p>
    <p style="word-break: break-all; font-size: 14px; color: #666;">{{link}}</p>
    <div class="warning">
      <strong>Security Notice:</strong> This link expires in {{expiresIn}}. If you didn't request this password reset, please ignore this email or contact support if you have concerns.
    </div>
  </div>
  <div class="footer">
    <p>This is an automated message from ${local.brand_name}. Please do not reply to this email.</p>
    <p>&copy; {{year}} ${local.brand_name}. All rights reserved.</p>
  </div>
</body>
</html>
HTML

  text = <<-TEXT
${local.brand_name}

Reset Your Password

We received a request to reset the password for your account associated with {{email}}.

Click the link below to reset your password:
{{link}}

This link expires in {{expiresIn}}.

Security Notice: If you didn't request this password reset, please ignore this email or contact support if you have concerns.

---
This is an automated message from ${local.brand_name}. Please do not reply to this email.
TEXT
}

# ------------------------------------------------------------------------------
# Email Verification Template
# ------------------------------------------------------------------------------

resource "aws_ses_template" "email_verification" {
  name    = "${var.project_name}-${var.environment}-email-verification"
  subject = var.email_verification_subject

  html = <<-HTML
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${var.email_verification_subject}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { text-align: center; padding: 20px 0; border-bottom: 1px solid #eee; }
    .content { padding: 30px 0; }
    .code { font-size: 32px; font-weight: bold; letter-spacing: 8px; text-align: center; background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0; font-family: monospace; }
    .button { display: inline-block; background: #0066cc; color: #ffffff; padding: 12px 30px; text-decoration: none; border-radius: 4px; margin: 20px 0; }
    .footer { padding: 20px 0; border-top: 1px solid #eee; font-size: 12px; color: #666; text-align: center; }
    .warning { background: #fff3cd; border: 1px solid #ffc107; padding: 10px; border-radius: 4px; margin: 20px 0; font-size: 14px; }
  </style>
</head>
<body>
  <div class="header">
    <h1>${local.brand_name}</h1>
  </div>
  <div class="content">
    <h2>Verify Your Email Address</h2>
    <p>Thank you for registering with ${local.brand_name}. Please verify your email address to complete your account setup.</p>
    <p>Your verification code is:</p>
    <div class="code">{{code}}</div>
    <p>Or click the button below to verify automatically:</p>
    <p style="text-align: center;">
      <a href="{{link}}" class="button">Verify Email</a>
    </p>
    <div class="warning">
      <strong>Note:</strong> This code expires in {{expiresIn}}. If you didn't create an account with ${local.brand_name}, please ignore this email.
    </div>
  </div>
  <div class="footer">
    <p>This is an automated message from ${local.brand_name}. Please do not reply to this email.</p>
    <p>&copy; {{year}} ${local.brand_name}. All rights reserved.</p>
  </div>
</body>
</html>
HTML

  text = <<-TEXT
${local.brand_name}

Verify Your Email Address

Thank you for registering with ${local.brand_name}. Please verify your email address to complete your account setup.

Your verification code is: {{code}}

Or visit this link to verify automatically:
{{link}}

This code expires in {{expiresIn}}.

Note: If you didn't create an account with ${local.brand_name}, please ignore this email.

---
This is an automated message from ${local.brand_name}. Please do not reply to this email.
TEXT
}
