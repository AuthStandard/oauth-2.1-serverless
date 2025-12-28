/**
 * SAML Strategy - SAML Response Parser
 *
 * Parses and validates SAML 2.0 responses from Identity Providers.
 *
 * Security Considerations:
 * - XML signature validation using xml-crypto (W3C XMLDsig compliant)
 * - Proper XML canonicalization (C14N) for signature verification
 * - Time window validation prevents replay attacks
 * - Audience validation ensures assertion is for this SP
 *
 * @see https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
 * @see https://www.w3.org/TR/xmldsig-core1/
 */

import { SignedXml } from 'xml-crypto';
import type { SAMLAssertion } from './types';

// =============================================================================
// XML Element Extraction
// =============================================================================

/**
 * Extract text content from an XML element by tag name.
 * Handles common SAML namespace prefixes (saml:, saml2:, none).
 *
 * @param xml - Raw XML string
 * @param tagName - Element tag name without namespace
 * @returns Element text content or null if not found
 */
export function extractXmlElement(xml: string, tagName: string): string | null {
    const patterns = [
        new RegExp(`<${tagName}[^>]*>([^<]*)</${tagName}>`, 's'),
        new RegExp(`<saml:${tagName}[^>]*>([^<]*)</saml:${tagName}>`, 's'),
        new RegExp(`<saml2:${tagName}[^>]*>([^<]*)</saml2:${tagName}>`, 's'),
    ];

    for (const pattern of patterns) {
        const match = xml.match(pattern);
        if (match?.[1]) {
            return match[1].trim();
        }
    }

    return null;
}

/**
 * Extract attribute value from SAML assertion.
 *
 * @param xml - Raw XML string
 * @param attributeName - SAML attribute name
 * @returns Attribute value or null if not found
 */
export function extractAttribute(xml: string, attributeName: string): string | null {
    // Escape special regex characters in attribute name
    const escapedName = attributeName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

    const attrPattern = new RegExp(
        `<(?:saml2?:)?Attribute[^>]*Name=["']${escapedName}["'][^>]*>` +
        `[\\s\\S]*?<(?:saml2?:)?AttributeValue[^>]*>([^<]*)</(?:saml2?:)?AttributeValue>`,
        'i'
    );

    const match = xml.match(attrPattern);
    return match?.[1]?.trim() || null;
}

/**
 * Extract audience restriction from SAML assertion.
 *
 * @param xml - Raw XML string
 * @returns Audience URI or null
 */
function extractAudience(xml: string): string | null {
    const pattern = /<(?:saml2?:)?Audience[^>]*>([^<]+)<\/(?:saml2?:)?Audience>/i;
    const match = xml.match(pattern);
    return match?.[1]?.trim() || null;
}

/**
 * Extract InResponseTo attribute for replay protection.
 *
 * @param xml - Raw XML string
 * @returns InResponseTo value or null
 */
function extractInResponseTo(xml: string): string | null {
    const match = xml.match(/InResponseTo=["']([^"']+)["']/);
    return match?.[1] || null;
}

// =============================================================================
// SAML Response Parsing
// =============================================================================

/**
 * Common SAML attribute names used by various IdPs.
 */
const COMMON_ATTRIBUTES = [
    // Email
    'email', 'Email', 'emailAddress', 'mail',
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
    'http://schemas.xmlsoap.org/claims/EmailAddress',
    // Given Name
    'firstName', 'givenName', 'given_name',
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
    // Family Name
    'lastName', 'familyName', 'family_name', 'surname', 'sn',
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
    // Display Name
    'displayName', 'name',
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
] as const;

/**
 * Parse a Base64-encoded SAML Response and extract assertion data.
 *
 * @param samlResponseB64 - Base64-encoded SAML Response
 * @returns Parsed SAML assertion
 * @throws Error if required elements are missing
 */
export function parseSamlResponse(samlResponseB64: string): SAMLAssertion {
    const xml = Buffer.from(samlResponseB64, 'base64').toString('utf-8');

    // Extract required elements
    const issuer = extractXmlElement(xml, 'Issuer');
    if (!issuer) {
        throw new Error('SAML Response missing Issuer element');
    }

    const nameId = extractXmlElement(xml, 'NameID');
    if (!nameId) {
        throw new Error('SAML Response missing NameID element');
    }

    // Extract all common attributes
    const attributes: Record<string, string> = {};
    for (const attr of COMMON_ATTRIBUTES) {
        const value = extractAttribute(xml, attr);
        if (value) {
            attributes[attr] = value;
        }
    }

    // Extract time conditions
    const notBeforeMatch = xml.match(/NotBefore=["']([^"']+)["']/);
    const notOnOrAfterMatch = xml.match(/NotOnOrAfter=["']([^"']+)["']/);

    // Extract security elements
    const audience = extractAudience(xml);
    const inResponseTo = extractInResponseTo(xml);

    return {
        issuer,
        nameId,
        attributes,
        notBefore: notBeforeMatch?.[1] ? new Date(notBeforeMatch[1]) : undefined,
        notOnOrAfter: notOnOrAfterMatch?.[1] ? new Date(notOnOrAfterMatch[1]) : undefined,
        audience: audience ?? undefined,
        inResponseTo: inResponseTo ?? undefined,
    };
}

// =============================================================================
// Signature Validation
// =============================================================================

/**
 * Validate SAML Response XML signature using W3C XMLDsig standard.
 *
 * Uses xml-crypto for proper XML canonicalization (C14N) and signature
 * verification. Supports both Response-level and Assertion-level signatures.
 *
 * @param samlResponseB64 - Base64-encoded SAML Response
 * @param certPem - IdP certificate in PEM format
 * @returns True if signature is valid
 *
 * @see https://www.w3.org/TR/xmldsig-core1/
 */
export function validateSignature(samlResponseB64: string, certPem: string): boolean {
    try {
        const xml = Buffer.from(samlResponseB64, 'base64').toString('utf-8');

        // Find all Signature elements (Response or Assertion level)
        const signatureMatches = xml.match(/<(?:ds:)?Signature[^>]*>[\s\S]*?<\/(?:ds:)?Signature>/g);

        if (!signatureMatches || signatureMatches.length === 0) {
            return false;
        }

        // Validate at least one signature
        for (const signatureXml of signatureMatches) {
            const sig = new SignedXml({
                publicCert: certPem,
            });

            // Load the signature
            sig.loadSignature(signatureXml);

            // Verify against the full XML document
            if (sig.checkSignature(xml)) {
                return true;
            }
        }

        return false;
    } catch {
        return false;
    }
}

// =============================================================================
// Assertion Validation
// =============================================================================

/**
 * Validate SAML assertion time conditions.
 *
 * @param assertion - Parsed SAML assertion
 * @param clockSkewSeconds - Allowed clock skew in seconds (default: 300)
 * @returns Validation result with error message if invalid
 */
export function validateTimeConditions(
    assertion: SAMLAssertion,
    clockSkewSeconds = 300
): { valid: boolean; error?: string } {
    const now = new Date();
    const skewMs = clockSkewSeconds * 1000;

    if (assertion.notBefore) {
        const notBeforeWithSkew = new Date(assertion.notBefore.getTime() - skewMs);
        if (now < notBeforeWithSkew) {
            return {
                valid: false,
                error: `Assertion not yet valid (NotBefore: ${assertion.notBefore.toISOString()})`,
            };
        }
    }

    if (assertion.notOnOrAfter) {
        const notOnOrAfterWithSkew = new Date(assertion.notOnOrAfter.getTime() + skewMs);
        if (now > notOnOrAfterWithSkew) {
            return {
                valid: false,
                error: `Assertion has expired (NotOnOrAfter: ${assertion.notOnOrAfter.toISOString()})`,
            };
        }
    }

    return { valid: true };
}

/**
 * Validate assertion audience matches our SP Entity ID.
 *
 * @param assertion - Parsed SAML assertion
 * @param expectedAudience - Our SP Entity ID
 * @returns True if audience matches or is not specified
 */
export function validateAudience(
    assertion: SAMLAssertion,
    expectedAudience: string
): boolean {
    if (!assertion.audience) {
        // No audience restriction - accept (some IdPs don't include it)
        return true;
    }

    return assertion.audience === expectedAudience;
}

// =============================================================================
// Email Extraction
// =============================================================================

/**
 * Extract email from SAML assertion using attribute mapping.
 *
 * @param assertion - Parsed SAML assertion
 * @param mapping - Attribute mapping configuration
 * @returns Email address or null if not found
 */
export function getEmailFromAssertion(
    assertion: SAMLAssertion,
    mapping: { email: string; givenName?: string; familyName?: string }
): string | null {
    // Try mapped attribute first
    const mappedEmail = assertion.attributes[mapping.email];
    if (mappedEmail) {
        return mappedEmail.toLowerCase();
    }

    // Fall back to NameID if it looks like an email
    if (assertion.nameId.includes('@')) {
        return assertion.nameId.toLowerCase();
    }

    // Try common email attribute names
    const emailAttrs = [
        'email', 'Email', 'emailAddress', 'mail',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
        'http://schemas.xmlsoap.org/claims/EmailAddress',
    ];

    for (const attr of emailAttrs) {
        const value = assertion.attributes[attr];
        if (value) {
            return value.toLowerCase();
        }
    }

    return null;
}

/**
 * Extract name attributes from SAML assertion.
 *
 * @param assertion - Parsed SAML assertion
 * @param mapping - Attribute mapping configuration
 * @returns Object with givenName and familyName
 */
export function getNameFromAssertion(
    assertion: SAMLAssertion,
    mapping: { email: string; givenName?: string; familyName?: string }
): { givenName?: string; familyName?: string } {
    let givenName: string | undefined;
    let familyName: string | undefined;

    // Try mapped attributes first
    if (mapping.givenName) {
        givenName = assertion.attributes[mapping.givenName];
    }
    if (mapping.familyName) {
        familyName = assertion.attributes[mapping.familyName];
    }

    // Fall back to common attribute names
    if (!givenName) {
        givenName = assertion.attributes['givenName']
            || assertion.attributes['firstName']
            || assertion.attributes['given_name']
            || assertion.attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname'];
    }

    if (!familyName) {
        familyName = assertion.attributes['familyName']
            || assertion.attributes['lastName']
            || assertion.attributes['surname']
            || assertion.attributes['sn']
            || assertion.attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'];
    }

    return { givenName: givenName ?? undefined, familyName: familyName ?? undefined };
}
