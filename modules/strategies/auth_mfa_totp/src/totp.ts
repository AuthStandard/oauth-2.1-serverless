/**
 * OAuth Server - TOTP Utilities
 *
 * Time-based One-Time Password generation and verification.
 * Implements RFC 6238 (TOTP) using the otplib library.
 *
 * Security:
 * - Secrets are 160 bits (20 bytes) of cryptographic randomness
 * - Window parameter allows for clock drift tolerance
 * - Backup codes are single-use and stored as SHA-256 hashes
 */

import { authenticator } from 'otplib';
import { createHash, randomBytes } from 'node:crypto';
import * as QRCode from 'qrcode';

// =============================================================================
// TOTP Configuration
// =============================================================================

/**
 * Configure TOTP parameters.
 */
export function configureTOTP(digits: number, period: number, window: number): void {
    authenticator.options = {
        digits,
        step: period,
        window,
    };
}

// =============================================================================
// Secret Generation
// =============================================================================

/**
 * Generate a cryptographically secure TOTP secret.
 * Returns a base32-encoded string suitable for authenticator apps.
 */
export function generateSecret(): string {
    return authenticator.generateSecret(20); // 160 bits
}

// =============================================================================
// QR Code Generation
// =============================================================================

/**
 * Generate a QR code data URL for authenticator app enrollment.
 *
 * @param secret - The TOTP secret
 * @param email - User's email address (account identifier)
 * @param issuer - Service name shown in authenticator app
 * @returns Data URL for the QR code image
 */
export async function generateQRCode(
    secret: string,
    email: string,
    issuer: string
): Promise<string> {
    const otpauthUrl = authenticator.keyuri(email, issuer, secret);
    return QRCode.toDataURL(otpauthUrl, {
        errorCorrectionLevel: 'M',
        margin: 2,
        width: 256,
    });
}

// =============================================================================
// TOTP Verification
// =============================================================================

/**
 * Verify a TOTP code against a secret.
 *
 * @param code - The 6-digit code from the authenticator app
 * @param secret - The user's TOTP secret
 * @returns True if the code is valid
 */
export function verifyTOTP(code: string, secret: string): boolean {
    try {
        return authenticator.verify({ token: code, secret });
    } catch {
        return false;
    }
}

// =============================================================================
// Backup Codes
// =============================================================================

/**
 * Generate backup codes for account recovery.
 * Each code is 8 characters of alphanumeric characters.
 *
 * @param count - Number of backup codes to generate
 * @returns Array of plaintext backup codes
 */
export function generateBackupCodes(count: number): string[] {
    const codes: string[] = [];
    const charset = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Excludes confusing chars: 0, O, I, 1

    for (let i = 0; i < count; i++) {
        const bytes = randomBytes(8);
        let code = '';
        for (let j = 0; j < 8; j++) {
            code += charset[bytes[j]! % charset.length];
        }
        // Format as XXXX-XXXX for readability
        codes.push(`${code.slice(0, 4)}-${code.slice(4)}`);
    }

    return codes;
}

/**
 * Hash a backup code for secure storage.
 */
export function hashBackupCode(code: string): string {
    // Normalize: remove dashes and convert to uppercase
    const normalized = code.replace(/-/g, '').toUpperCase();
    return createHash('sha256').update(normalized).digest('hex');
}

/**
 * Verify a backup code against stored hashes.
 *
 * @param code - The backup code to verify
 * @param hashes - Array of stored backup code hashes
 * @returns The matching hash if found, null otherwise
 */
export function verifyBackupCode(code: string, hashes: string[]): string | null {
    const codeHash = hashBackupCode(code);
    return hashes.includes(codeHash) ? codeHash : null;
}
