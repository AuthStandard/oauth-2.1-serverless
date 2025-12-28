# ==============================================================================
# OAuth Server - S3 Backend Configuration
# ==============================================================================
# Backend config values are injected via Makefile using -backend-config flags.
# This allows the same configuration to work across all environments.
# ==============================================================================

terraform {
  backend "s3" {
    # These values are provided via -backend-config in the Makefile:
    #   -backend-config="bucket=<TF_STATE_BUCKET>"
    #   -backend-config="key=<TF_STATE_KEY_PREFIX>/<env>/terraform.tfstate"
    #   -backend-config="region=<AWS_REGION>"
    #   -backend-config="dynamodb_table=<TF_STATE_LOCK_TABLE>"  (optional)
    #   -backend-config="encrypt=true"

    # Encryption is always enabled
    encrypt = true
  }
}
