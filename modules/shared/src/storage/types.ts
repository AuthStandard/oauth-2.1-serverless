/**
 * OAuth Server - Storage Adapter Types
 *
 * Type definitions for the DynamoDB storage adapter.
 *
 * @module storage/types
 */

// =============================================================================
// Storage Adapter Configuration
// =============================================================================

/**
 * Configuration options for the StorageAdapter.
 */
export interface StorageAdapterConfig {
    /** DynamoDB table name (injected from environment) */
    tableName: string;
    /** AWS region (optional, defaults to environment) */
    region?: string;
}
