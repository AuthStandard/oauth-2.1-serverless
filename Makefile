# ==============================================================================
# OAuth Server - Makefile
# ==============================================================================
# Terraform workflow automation.
#
# Usage:
#   1. Set ENVIRONMENT in config.mk
#   2. Edit environments/<env>/config.mk with AWS and backend settings
#   3. Edit environments/<env>/terraform.tfvars with your variables
#   4. Run: make init
#   5. Run: make plan
#   6. Run: make apply
#
# TypeScript builds are handled automatically by Terraform via null_resource.
# ==============================================================================

# Load global config (environment selector)
-include config.mk

# ==============================================================================
# Validation - Stage 1 (before loading env config)
# ==============================================================================

ifndef ENVIRONMENT
  $(error ENVIRONMENT is not set. Edit config.mk)
endif

ENV_DIR := environments/$(ENVIRONMENT)

# Load environment-specific config
-include $(ENV_DIR)/config.mk

# ==============================================================================
# Validation - Stage 2 (after loading env config)
# ==============================================================================

ifndef AWS_REGION
  $(error AWS_REGION is not set. Edit $(ENV_DIR)/config.mk)
endif

ifndef TF_STATE_BUCKET
  $(error TF_STATE_BUCKET is not set. Create an S3 bucket and set it in $(ENV_DIR)/config.mk)
endif

# ==============================================================================
# Variables
# ==============================================================================

TF_STATE_KEY := $(TF_STATE_KEY_PREFIX)/$(ENVIRONMENT)/terraform.tfstate

ifdef AWS_PROFILE
  AWS_FLAGS := AWS_PROFILE=$(AWS_PROFILE)
endif

BACKEND_FLAGS := \
  -backend-config="region=$(AWS_REGION)" \
  -backend-config="bucket=$(TF_STATE_BUCKET)" \
  -backend-config="key=$(TF_STATE_KEY)" \
  -backend-config="encrypt=true"

ifdef TF_STATE_LOCK_TABLE
  BACKEND_FLAGS += -backend-config="dynamodb_table=$(TF_STATE_LOCK_TABLE)"
endif

# ==============================================================================
# Main Targets
# ==============================================================================

.PHONY: help
help: ## Show help
	@echo "OAuth Server - $(ENVIRONMENT) environment"
	@echo ""
	@echo "Commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

.PHONY: init
init: _validate ## Initialize Terraform
	@cd $(ENV_DIR) && $(AWS_FLAGS) terraform init $(BACKEND_FLAGS)

.PHONY: plan
plan: _validate ## Preview changes
	@cd $(ENV_DIR) && $(AWS_FLAGS) terraform plan -var-file=terraform.tfvars -out=tfplan

.PHONY: apply
apply: _validate ## Apply changes (builds TypeScript automatically)
	@if [ -f "$(ENV_DIR)/tfplan" ]; then \
		cd $(ENV_DIR) && $(AWS_FLAGS) terraform apply tfplan && rm -f tfplan; \
	else \
		cd $(ENV_DIR) && $(AWS_FLAGS) terraform apply -var-file=terraform.tfvars -auto-approve; \
	fi

.PHONY: destroy
destroy: _validate ## Destroy infrastructure
	@echo "WARNING: This will destroy all resources in $(ENVIRONMENT)"
	@read -p "Type 'destroy-$(ENVIRONMENT)' to confirm: " confirm && \
		[ "$$confirm" = "destroy-$(ENVIRONMENT)" ] && \
		cd $(ENV_DIR) && $(AWS_FLAGS) terraform destroy -var-file=terraform.tfvars -auto-approve

# ==============================================================================
# Utility Targets
# ==============================================================================

.PHONY: output
output: ## Show outputs
	@cd $(ENV_DIR) && $(AWS_FLAGS) terraform output

.PHONY: fmt
fmt: ## Format all Terraform files
	@echo "Formatting Terraform files..."
	@terraform fmt -recursive
	@echo "Done"

.PHONY: fmt-check
fmt-check: ## Check Terraform formatting (CI-friendly)
	@terraform fmt -recursive -check

.PHONY: validate
validate: _validate ## Validate configuration
	@cd $(ENV_DIR) && terraform validate

.PHONY: lint
lint: fmt-check validate ## Run all checks (format + validate)

.PHONY: clean
clean: ## Clean generated files
	@find . -name ".terraform" -type d -exec rm -rf {} + 2>/dev/null || true
	@find . -name "tfplan" -delete 2>/dev/null || true
	@find . -name ".terraform.lock.hcl" -delete 2>/dev/null || true
	@echo "Cleaned"

.PHONY: seed
seed: ## Seed DynamoDB with initial data
	@cd tests/live/scripts && npx ts-node seed.ts

# ==============================================================================
# Internal
# ==============================================================================

.PHONY: _validate
_validate:
	@[ -d "$(ENV_DIR)" ] || (echo "Error: $(ENV_DIR) does not exist" && exit 1)
	@[ -f "$(ENV_DIR)/config.mk" ] || (echo "Error: $(ENV_DIR)/config.mk does not exist" && exit 1)
	@[ -f "$(ENV_DIR)/terraform.tfvars" ] || (echo "Error: $(ENV_DIR)/terraform.tfvars does not exist. Copy terraform.tfvars.example and configure it." && exit 1)
