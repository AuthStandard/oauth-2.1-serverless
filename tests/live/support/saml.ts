/**
 * SAML Test Helpers
 *
 * Generates signed SAML assertions for testing the ACS endpoint.
 *
 * Uses a keypair seeded in DynamoDB via seed-saml.ts script.
 * The private key is stored in saml-fixtures.json for signing test assertions.
 */

import * as crypto from 'crypto';
import { SignedXml } from 'xml-crypto';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

// =============================================================================
// Load SAML Fixtures
// =============================================================================

const fixturesPath = join(__dirname, '..', 'saml-fixtures.json');

interface SAMLFixtures {
  issuer: string;
  privateKey: string;
  publicKey: string;
}

let samlFixtures: SAMLFixtures | null = null;

function loadSAMLFixtures(): SAMLFixtures {
  if (samlFixtures) return samlFixtures;

  if (!existsSync(fixturesPath)) {
    throw new Error(
      'SAML fixtures not found. Run: npx ts-node scripts/seed-saml.ts'
    );
  }

  samlFixtures = JSON.parse(readFileSync(fixturesPath, 'utf-8'));
  return samlFixtures!;
}

export function getSAMLIssuer(): string {
  return loadSAMLFixtures().issuer;
}

export function getSAMLPrivateKey(): string {
  return loadSAMLFixtures().privateKey;
}

export function getSAMLPublicKey(): string {
  return loadSAMLFixtures().publicKey;
}

// =============================================================================
// SAML Assertion Generator
// =============================================================================

export interface SAMLAssertionOptions {
  /** Subject email */
  email: string;
  /** Subject name ID */
  nameId?: string;
  /** Audience (SP Entity ID) */
  audience: string;
  /** Assertion ID */
  assertionId?: string;
  /** InResponseTo (session ID) */
  inResponseTo?: string;
  /** NotBefore offset in seconds (negative for past) */
  notBeforeOffset?: number;
  /** NotOnOrAfter offset in seconds */
  notOnOrAfterOffset?: number;
  /** Additional attributes */
  attributes?: Record<string, string>;
  /** Skip signing (for invalid signature tests) */
  skipSigning?: boolean;
  /** Use wrong key for signing (for bad signature tests) */
  useWrongKey?: boolean;
}

/**
 * Generate a SAML Response with signed assertion.
 */
export function generateSAMLResponse(options: SAMLAssertionOptions): string {
  const now = new Date();
  const assertionId = options.assertionId || `_${crypto.randomUUID()}`;
  const responseId = `_${crypto.randomUUID()}`;
  const nameId = options.nameId || options.email;

  // Time conditions
  const notBefore = new Date(now.getTime() + (options.notBeforeOffset || -300) * 1000);
  const notOnOrAfter = new Date(now.getTime() + (options.notOnOrAfterOffset || 300) * 1000);

  // Build attributes XML
  let attributesXml = '';
  const attrs = {
    email: options.email,
    ...options.attributes,
  };

  for (const [name, value] of Object.entries(attrs)) {
    attributesXml += `
        <saml:Attribute Name="${escapeXml(name)}">
          <saml:AttributeValue>${escapeXml(value)}</saml:AttributeValue>
        </saml:Attribute>`;
  }

  // Build the assertion (without signature - will be added by xml-crypto)
  const issuer = getSAMLIssuer();
  const assertion = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}" IssueInstant="${now.toISOString()}" Version="2.0">
    <saml:Issuer>${escapeXml(issuer)}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${escapeXml(nameId)}</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore="${notBefore.toISOString()}" NotOnOrAfter="${notOnOrAfter.toISOString()}">
      <saml:AudienceRestriction>
        <saml:Audience>${escapeXml(options.audience)}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>${attributesXml}
    </saml:AttributeStatement>
  </saml:Assertion>`;

  // Build the response wrapper
  const inResponseToAttr = options.inResponseTo
    ? ` InResponseTo="${escapeXml(options.inResponseTo)}"`
    : '';

  let response = `<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="${responseId}" Version="2.0" IssueInstant="${now.toISOString()}"${inResponseToAttr}>
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${escapeXml(issuer)}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  ${assertion}
</samlp:Response>`;

  // Sign the assertion if not skipped
  if (!options.skipSigning) {
    const keyToUse = options.useWrongKey
      ? crypto.generateKeyPairSync('rsa', {
          modulusLength: 2048,
          privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        }).privateKey
      : getSAMLPrivateKey();

    response = signSAMLAssertion(response, assertionId, keyToUse);
  }

  return response;
}

/**
 * Sign a SAML assertion using xml-crypto.
 */
function signSAMLAssertion(xml: string, assertionId: string, privateKey: string): string {
  const sig = new SignedXml({
    privateKey,
    canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
    signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
  });

  sig.addReference({
    xpath: `//*[@ID='${assertionId}']`,
    transforms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#',
    ],
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
  });

  sig.computeSignature(xml, {
    location: { reference: `//*[@ID='${assertionId}']`, action: 'prepend' },
  });

  return sig.getSignedXml();
}

/**
 * Encode SAML Response as Base64 for POST binding.
 */
export function encodeSAMLResponse(xml: string): string {
  return Buffer.from(xml, 'utf-8').toString('base64');
}

/**
 * Escape XML special characters.
 */
function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}
