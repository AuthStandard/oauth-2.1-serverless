/**
 * OIDC RP-Initiated Logout - KMS Operations
 *
 * AWS KMS operations for retrieving the public key used for JWT verification.
 *
 * @see https://docs.aws.amazon.com/kms/latest/APIReference/API_GetPublicKey.html
 */

import { KMSClient, GetPublicKeyCommand } from '@aws-sdk/client-kms';

// =============================================================================
// KMS Client Singleton
// =============================================================================

/** Cached KMS client for Lambda container reuse */
let kmsClient: KMSClient | null = null;

/** Cached public key PEM and associated key ID */
let publicKeyCache: { pem: string; keyId: string } | null = null;

/**
 * Get or create KMS client singleton.
 * Reuses client across Lambda invocations for connection pooling.
 */
function getKmsClient(): KMSClient {
    if (!kmsClient) {
        kmsClient = new KMSClient({});
    }
    return kmsClient;
}

// =============================================================================
// Public Key Retrieval
// =============================================================================

/**
 * Retrieve and cache the public key from KMS in PEM format.
 *
 * The public key is cached for the Lambda container lifetime to minimize
 * KMS API calls. This is safe because the key doesn't change during
 * a Lambda container's lifetime.
 *
 * @param kmsKeyId - KMS Key ID or ARN
 * @returns PEM-encoded public key
 * @throws Error if KMS returns no public key
 */
export async function getPublicKey(kmsKeyId: string): Promise<string> {
    // Return cached key if available and matches requested key
    if (publicKeyCache?.keyId === kmsKeyId) {
        return publicKeyCache.pem;
    }

    // Fetch public key from KMS
    const result = await getKmsClient().send(
        new GetPublicKeyCommand({ KeyId: kmsKeyId })
    );

    if (!result.PublicKey) {
        throw new Error('KMS returned no public key');
    }

    // Convert binary key to PEM format
    const base64Key = Buffer.from(result.PublicKey).toString('base64');
    const pemLines = base64Key.match(/.{1,64}/g) ?? [];
    const pem = `-----BEGIN PUBLIC KEY-----\n${pemLines.join('\n')}\n-----END PUBLIC KEY-----`;

    // Cache for future invocations
    publicKeyCache = { pem, keyId: kmsKeyId };

    return pem;
}
