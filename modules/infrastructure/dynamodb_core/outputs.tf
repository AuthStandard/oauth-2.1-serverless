# ==============================================================================
# DynamoDB Core Module - Outputs
# ==============================================================================
# These outputs are consumed by protocol and strategy modules for:
#   - Lambda environment variables (table_name)
#   - IAM policy resources (table_arn, gsi1_arn, encryption_key_arn)
#   - Global Tables replication (stream_arn)
#
# Single Table Design Access Patterns:
#   - table_arn: Required for PutItem, GetItem, UpdateItem, DeleteItem
#   - gsi1_arn: Required for Query operations on GSI1 (email lookups, client listing)
#   - encryption_key_arn: Required for kms:Decrypt when reading encrypted attributes
#
# Usage in Protocol Modules:
#   module "oauth2_token" {
#     dynamodb_table_name         = module.dynamodb_core.table_name
#     dynamodb_table_arn          = module.dynamodb_core.table_arn
#     dynamodb_gsi1_arn           = module.dynamodb_core.gsi1_arn
#     dynamodb_encryption_key_arn = module.dynamodb_core.encryption_key_arn
#   }
# ==============================================================================

output "table_name" {
  description = "DynamoDB table name for Lambda TABLE_NAME environment variable"
  value       = aws_dynamodb_table.main.name
}

output "table_arn" {
  description = "DynamoDB table ARN for IAM policy Resource blocks (PutItem, GetItem, UpdateItem, DeleteItem, Query on primary key)"
  value       = aws_dynamodb_table.main.arn
}

output "table_id" {
  description = "DynamoDB table ID (same as name for DynamoDB)"
  value       = aws_dynamodb_table.main.id
}

output "gsi1_arn" {
  description = "GSI1 ARN for IAM policies requiring index query permissions (email lookups, client listing)"
  value       = "${aws_dynamodb_table.main.arn}/index/GSI1"
}

output "stream_arn" {
  description = "DynamoDB Streams ARN for Global Tables replication or event triggers"
  value       = aws_dynamodb_table.main.stream_arn
}

output "stream_label" {
  description = "DynamoDB Streams label timestamp for stream consumer identification"
  value       = aws_dynamodb_table.main.stream_label
}

output "encryption_key_arn" {
  description = "KMS key ARN for DynamoDB encryption. Lambda roles need kms:Decrypt permission for reading encrypted data."
  value       = aws_kms_key.dynamodb_encryption.arn
}

output "encryption_key_id" {
  description = "KMS key ID for DynamoDB encryption"
  value       = aws_kms_key.dynamodb_encryption.key_id
}

output "encryption_key_alias" {
  description = "KMS key alias for DynamoDB encryption"
  value       = aws_kms_alias.dynamodb_encryption.name
}
