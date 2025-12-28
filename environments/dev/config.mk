# ==============================================================================
# OAuth Server - Dev Environment Configuration
# ==============================================================================
# Environment-specific AWS and backend settings.
# ==============================================================================

# ------------------------------------------------------------------------------
# AWS Configuration
# ------------------------------------------------------------------------------

# AWS Region for deployment
AWS_REGION := us-east-1

# AWS Profile to use (leave empty for default credentials)
AWS_PROFILE :=

# ------------------------------------------------------------------------------
# Terraform Backend (S3)
# Create these resources manually before first deployment:
#   1. S3 bucket for state storage
#   2. DynamoDB table for state locking (optional but recommended)
# ------------------------------------------------------------------------------

# S3 bucket name for Terraform state (REQUIRED - must be globally unique)
TF_STATE_BUCKET := tform-storage

# S3 key prefix for state files
TF_STATE_KEY_PREFIX := oauth-server

# DynamoDB table for state locking (optional, leave empty to disable)
TF_STATE_LOCK_TABLE :=
