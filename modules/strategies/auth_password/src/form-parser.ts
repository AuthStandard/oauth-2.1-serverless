/**
 * OAuth Server - Form Body Parser
 *
 * Parses URL-encoded form data from POST requests.
 */

// =============================================================================
// Form Body Parsing
// =============================================================================

/**
 * Parse a URL-encoded form body into a key-value object.
 * Handles base64-encoded bodies from API Gateway.
 *
 * @param body - The raw request body
 * @param isBase64Encoded - Whether the body is base64 encoded
 * @returns Parsed form data as a Record
 */
export function parseFormBody(
    body: string | null | undefined,
    isBase64Encoded: boolean
): Record<string, string> {
    if (!body) {
        return {};
    }

    const decodedBody = isBase64Encoded
        ? Buffer.from(body, 'base64').toString('utf-8')
        : body;

    const params = new URLSearchParams(decodedBody);
    const result: Record<string, string> = {};

    for (const [key, value] of params) {
        result[key] = value;
    }

    return result;
}
