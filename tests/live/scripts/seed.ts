#!/usr/bin/env npx ts-node
/**
 * DynamoDB Seed Script
 *
 * Seeds DynamoDB from seed.json, outputs fixtures.json
 *
 * Usage: npx ts-node seed.ts
 */

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand } from '@aws-sdk/lib-dynamodb';
import { createHash, randomBytes } from 'crypto';
import { readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import argon2 from 'argon2';

// Load config
const config = JSON.parse(readFileSync(join(__dirname, '..', 'config.json'), 'utf-8'));
const seedData: Record<string, unknown>[] = JSON.parse(readFileSync(join(__dirname, 'data', 'seed.json'), 'utf-8'));

const client = new DynamoDBClient({ region: config.awsRegion });
const docClient = DynamoDBDocumentClient.from(client);

const fixtures: {
  clients: Record<string, { client_id: string; client_secret?: string; redirect_uri?: string }>;
  users: Record<string, { email: string; password: string; sub: string }>;
} = { clients: {}, users: {} };

async function seed() {
  console.log(`\nSeeding ${config.dynamodbTable} (${seedData.length} items)...\n`);

  for (const item of seedData) {
    if (item.entityType === 'CLIENT') {
      const clientId = item.clientId as string;
      const redirectUris = item.redirectUris as string[];

      if (item.clientType === 'CONFIDENTIAL') {
        const secret = randomBytes(32).toString('hex');
        item.clientSecretHash = createHash('sha256').update(secret).digest('hex');
        fixtures.clients[clientId] = { client_id: clientId, client_secret: secret, redirect_uri: redirectUris?.[0] };
      } else {
        fixtures.clients[clientId] = { client_id: clientId, redirect_uri: redirectUris?.[0] };
      }
    }

    if (item.entityType === 'USER' && item.password) {
      const password = item.password as string;
      item.passwordHash = await argon2.hash(password, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 4 });
      fixtures.users[item.sub as string] = { email: item.email as string, password, sub: item.sub as string };
      delete item.password;
    }

    await docClient.send(new PutCommand({ TableName: config.dynamodbTable, Item: item }));
    console.log(`  ✓ ${item.entityType}: ${item.PK}`);
  }

  writeFileSync(join(__dirname, '..', 'fixtures.json'), JSON.stringify(fixtures, null, 2));
  console.log(`\n✓ Done. Fixtures written to fixtures.json\n`);

  for (const [id, c] of Object.entries(fixtures.clients)) {
    if (c.client_secret) console.log(`[${id}] secret: ${c.client_secret}`);
  }
  for (const [id, u] of Object.entries(fixtures.users)) {
    console.log(`[${id}] ${u.email} / ${u.password}`);
  }
}

seed().catch((e) => { console.error(e); process.exit(1); });
