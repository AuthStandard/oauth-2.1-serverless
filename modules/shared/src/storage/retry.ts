/**
 * OAuth Server - DynamoDB Retry Utilities
 *
 * Implements exponential backoff with jitter for transient DynamoDB failures.
 * Handles throttling, provisioned throughput exceeded, and transient errors.
 *
 * Retry Strategy:
 * - Exponential backoff: 100ms, 200ms, 400ms, 800ms, 1600ms
 * - Full jitter to prevent thundering herd
 * - Maximum 5 retries by default
 * - Only retries transient/throttling errors
 *
 * @see https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/
 */

// =============================================================================
// Types
// =============================================================================

export interface RetryConfig {
    /** Maximum number of retry attempts (default: 5) */
    maxRetries: number;
    /** Base delay in milliseconds (default: 100) */
    baseDelayMs: number;
    /** Maximum delay in milliseconds (default: 5000) */
    maxDelayMs: number;
}

/** Default retry configuration */
export const DEFAULT_RETRY_CONFIG: RetryConfig = {
    maxRetries: 5,
    baseDelayMs: 100,
    maxDelayMs: 5000,
};

// =============================================================================
// Retryable Error Detection
// =============================================================================

/**
 * Error names that indicate transient failures worth retrying.
 */
const RETRYABLE_ERROR_NAMES = new Set([
    'ProvisionedThroughputExceededException',
    'ThrottlingException',
    'RequestLimitExceeded',
    'InternalServerError',
    'ServiceUnavailable',
    'TransactionConflictException',
]);

/**
 * HTTP status codes that indicate transient failures.
 */
const RETRYABLE_STATUS_CODES = new Set([
    429, // Too Many Requests
    500, // Internal Server Error
    502, // Bad Gateway
    503, // Service Unavailable
    504, // Gateway Timeout
]);

/**
 * Determine if an error is retryable.
 *
 * @param error - The error to check
 * @returns True if the error is transient and worth retrying
 */
export function isRetryableError(error: unknown): boolean {
    if (!error || typeof error !== 'object') {
        return false;
    }

    const err = error as Record<string, unknown>;

    // Check error name
    if (typeof err.name === 'string' && RETRYABLE_ERROR_NAMES.has(err.name)) {
        return true;
    }

    // Check $metadata for AWS SDK v3 errors
    if (err.$metadata && typeof err.$metadata === 'object') {
        const metadata = err.$metadata as Record<string, unknown>;
        if (typeof metadata.httpStatusCode === 'number' && RETRYABLE_STATUS_CODES.has(metadata.httpStatusCode)) {
            return true;
        }
    }

    // Check retryable flag (some AWS errors set this)
    if (err.$retryable === true || err.retryable === true) {
        return true;
    }

    return false;
}

// =============================================================================
// Delay Calculation
// =============================================================================

/**
 * Calculate delay with exponential backoff and full jitter.
 *
 * Full jitter provides better distribution than equal jitter and
 * prevents thundering herd problems in distributed systems.
 *
 * @param attempt - Current attempt number (0-indexed)
 * @param config - Retry configuration
 * @returns Delay in milliseconds
 */
export function calculateDelay(attempt: number, config: RetryConfig = DEFAULT_RETRY_CONFIG): number {
    // Exponential backoff: baseDelay * 2^attempt
    const exponentialDelay = config.baseDelayMs * Math.pow(2, attempt);

    // Cap at maximum delay
    const cappedDelay = Math.min(exponentialDelay, config.maxDelayMs);

    // Full jitter: random value between 0 and cappedDelay
    return Math.floor(Math.random() * cappedDelay);
}

/**
 * Sleep for the specified duration.
 *
 * @param ms - Duration in milliseconds
 * @returns Promise that resolves after the specified duration
 */
export function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// =============================================================================
// Retry Wrapper
// =============================================================================

/**
 * Execute an async operation with retry logic.
 *
 * @param operation - The async operation to execute
 * @param config - Retry configuration (optional)
 * @returns The result of the operation
 * @throws The last error if all retries are exhausted
 *
 * @example
 * ```typescript
 * const result = await withRetry(async () => {
 *   return await dynamoClient.send(new GetCommand({ ... }));
 * });
 * ```
 */
export async function withRetry<T>(
    operation: () => Promise<T>,
    config: RetryConfig = DEFAULT_RETRY_CONFIG
): Promise<T> {
    let lastError: unknown;

    for (let attempt = 0; attempt <= config.maxRetries; attempt++) {
        try {
            return await operation();
        } catch (error) {
            lastError = error;

            // Don't retry if it's not a retryable error
            if (!isRetryableError(error)) {
                throw error;
            }

            // Don't retry if we've exhausted all attempts
            if (attempt >= config.maxRetries) {
                throw error;
            }

            // Wait before retrying
            const delay = calculateDelay(attempt, config);
            await sleep(delay);
        }
    }

    // This should never be reached, but TypeScript needs it
    throw lastError;
}

/**
 * Execute a batch operation with retry logic for unprocessed items.
 *
 * DynamoDB batch operations may return unprocessed items due to throttling.
 * This function retries unprocessed items with exponential backoff.
 *
 * @param operation - Function that performs batch operation and returns unprocessed count
 * @param config - Retry configuration (optional)
 * @returns Total number of successfully processed items
 */
export async function withBatchRetry(
    operation: () => Promise<{ processed: number; unprocessed: number }>,
    config: RetryConfig = DEFAULT_RETRY_CONFIG
): Promise<number> {
    let totalProcessed = 0;
    let attempt = 0;

    while (attempt <= config.maxRetries) {
        const result = await operation();
        totalProcessed += result.processed;

        if (result.unprocessed === 0) {
            return totalProcessed;
        }

        // Wait before retrying unprocessed items
        const delay = calculateDelay(attempt, config);
        await sleep(delay);
        attempt++;
    }

    return totalProcessed;
}
