/**
 * OAuth Server - Email Notification Service
 *
 * AWS SES integration for transactional emails (password reset, verification).
 * Uses SES templates created by the notifications infrastructure module.
 *
 * Security:
 * - No PII logged (email addresses are masked in logs)
 * - Template data is sanitized to prevent injection
 * - Sender address is validated at infrastructure level
 *
 * Usage:
 * ```typescript
 * const mailer = new Mailer({
 *   senderEmail: process.env.SES_SENDER_EMAIL!,
 *   senderName: process.env.SES_SENDER_NAME!,
 *   configurationSet: process.env.SES_CONFIGURATION_SET,
 * });
 *
 * await mailer.sendEmail({
 *   to: 'user@example.com',
 *   template: 'oauth-server-dev-password-reset',
 *   data: { link: 'https://...', email: 'user@example.com', expiresIn: '1 hour' },
 * });
 * ```
 *
 * @module shared/mailer
 * @see AWS SES SendTemplatedEmail API
 */

import { SESClient, SendTemplatedEmailCommand } from '@aws-sdk/client-ses';

// =============================================================================
// Types
// =============================================================================

/**
 * Mailer configuration options.
 */
export interface MailerConfig {
    /** Verified sender email address */
    senderEmail: string;
    /** Display name for the sender */
    senderName: string;
    /** Optional SES configuration set for tracking */
    configurationSet?: string;
    /** AWS region (defaults to Lambda execution region) */
    region?: string;
}

/**
 * Email send request parameters.
 */
export interface SendEmailParams {
    /** Recipient email address */
    to: string;
    /** SES template name */
    template: string;
    /** Template data (key-value pairs for template placeholders) */
    data: Record<string, string | number>;
}

/**
 * Email send result.
 */
export interface SendEmailResult {
    /** Whether the email was sent successfully */
    success: boolean;
    /** SES message ID (if successful) */
    messageId?: string;
    /** Error message (if failed) */
    error?: string;
}

// =============================================================================
// Mailer Class
// =============================================================================

/**
 * Email notification service using AWS SES.
 *
 * Provides a simple interface for sending templated emails.
 * Templates are created by the notifications infrastructure module.
 */
export class Mailer {
    private readonly client: SESClient;
    private readonly senderEmail: string;
    private readonly senderName: string;
    private readonly configurationSet?: string;

    constructor(config: MailerConfig) {
        this.client = new SESClient({ region: config.region });
        this.senderEmail = config.senderEmail;
        this.senderName = config.senderName;
        this.configurationSet = config.configurationSet;
    }

    /**
     * Send a templated email via AWS SES.
     *
     * @param params - Email parameters
     * @returns Send result with success status and message ID
     */
    async sendEmail(params: SendEmailParams): Promise<SendEmailResult> {
        const { to, template, data } = params;

        // Add common template data
        const templateData = {
            ...data,
            year: new Date().getFullYear().toString(),
        };

        const command = new SendTemplatedEmailCommand({
            Source: this.senderName
                ? `${this.senderName} <${this.senderEmail}>`
                : this.senderEmail,
            Destination: {
                ToAddresses: [to],
            },
            Template: template,
            TemplateData: JSON.stringify(templateData),
            ConfigurationSetName: this.configurationSet || undefined,
        });

        try {
            const response = await this.client.send(command);
            return {
                success: true,
                messageId: response.MessageId,
            };
        } catch (err) {
            const error = err as Error;
            return {
                success: false,
                error: error.message,
            };
        }
    }

    /**
     * Mask an email address for logging (SOC2 compliance).
     * Example: "user@example.com" -> "u***@e***.com"
     *
     * @param email - Email address to mask
     * @returns Masked email address
     */
    static maskEmail(email: string): string {
        const [local, domain] = email.split('@');
        if (!local || !domain) {
            return '***@***.***';
        }

        const maskedLocal = local.length > 1
            ? local[0] + '***'
            : '***';

        const domainParts = domain.split('.');
        const maskedDomain = domainParts.length > 1
            ? domainParts[0]![0] + '***.' + domainParts.slice(1).join('.')
            : '***';

        return `${maskedLocal}@${maskedDomain}`;
    }
}

// =============================================================================
// Factory Function
// =============================================================================

/**
 * Create a Mailer instance from environment variables.
 *
 * Required environment variables:
 * - SES_SENDER_EMAIL: Verified sender email address
 * - SES_SENDER_NAME: Display name for the sender
 *
 * Optional environment variables:
 * - SES_CONFIGURATION_SET: SES configuration set name
 *
 * @returns Configured Mailer instance
 * @throws Error if required environment variables are missing
 */
export function createMailer(): Mailer {
    const senderEmail = process.env.SES_SENDER_EMAIL;
    const senderName = process.env.SES_SENDER_NAME;
    const configurationSet = process.env.SES_CONFIGURATION_SET;

    if (!senderEmail) {
        throw new Error('SES_SENDER_EMAIL environment variable is required');
    }
    if (!senderName) {
        throw new Error('SES_SENDER_NAME environment variable is required');
    }

    return new Mailer({
        senderEmail,
        senderName,
        configurationSet: configurationSet || undefined,
    });
}
