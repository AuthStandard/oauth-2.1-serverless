#!/usr/bin/env npx ts-node
/**
 * SAML Provider Seed Script
 *
 * Seeds a test SAML provider in DynamoDB with a generated certificate.
 * Also outputs the certificate to fixtures for test verification.
 *
 * Usage: npx ts-node seed-saml.ts
 */

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand } from '@aws-sdk/lib-dynamodb';
import { generateKeyPairSync } from 'crypto';
import { readFileSync, writeFileSync } from 'fs';
import { join } from 'path';

// Load config
const config = JSON.parse(readFileSync(join(__dirname, '..', 'config.json'), 'utf-8'));

const client = new DynamoDBClient({ region: config.awsRegion });
const docClient = DynamoDBDocumentClient.from(client);

const TEST_SAML_ISSUER = 'https://test-idp.example.com';

async function seedSamlProvider() {
  console.log('\nGenerating test SAML keypair...\n');

  // Generate RSA keypair
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  // Create SAML provider item
  const samlProvider = {
    PK: `SAML#${TEST_SAML_ISSUER}`,
    SK: 'CONFIG',
    entityType: 'SAML_PROVIDER',
    issuer: TEST_SAML_ISSUER,
    certPem: publicKey,
    ssoUrl: `${TEST_SAML_ISSUER}/sso`,
    nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    attributeMapping: {
      email: 'email',
      givenName: 'firstName',
      familyName: 'lastName',
    },
    enabled: true,
    displayName: 'Test SAML IdP',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  // Seed to DynamoDB
  await docClient.send(new PutCommand({
    TableName: config.dynamodbTable,
    Item: samlProvider,
  }));

  console.log(`  ✓ SAML_PROVIDER: ${samlProvider.PK}`);

  // Save keypair to fixtures for tests
  const samlFixtures = {
    issuer: TEST_SAML_ISSUER,
    privateKey,
    publicKey,
  };

  writeFileSync(
    join(__dirname, '..', 'saml-fixtures.json'),
    JSON.stringify(samlFixtures, null, 2)
  );

  console.log('\n✓ Done. SAML fixtures written to saml-fixtures.json\n');
  console.log(`Issuer: ${TEST_SAML_ISSUER}`);
}

seedSamlProvider().catch((e) => {
  console.error(e);
  process.exit(1);
});
