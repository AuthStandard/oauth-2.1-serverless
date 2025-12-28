/**
 * Global Test Configuration
 */

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load config
const configData = JSON.parse(readFileSync(join(__dirname, 'config.json'), 'utf-8'));

export const config = {
  apiBaseUrl: configData.apiBaseUrl as string,
  dynamodbTable: configData.dynamodbTable as string,
  awsRegion: configData.awsRegion as string,
};

export const API_BASE_URL = config.apiBaseUrl;
export const DYNAMODB_TABLE = config.dynamodbTable;
export const AWS_REGION = config.awsRegion;

// Endpoint paths (configurable)
export const ENDPOINTS = {
  discovery: configData.endpoints.discovery,
  authorize: configData.endpoints.authorize,
  token: configData.endpoints.token,
  keys: configData.endpoints.keys,
  userinfo: configData.endpoints.userinfo,
  revoke: configData.endpoints.revoke,
  introspect: configData.endpoints.introspect,
  logout: configData.endpoints.logout,
  register: configData.endpoints.register,
  scimUsers: configData.endpoints.scimUsers,
  scimGroups: configData.endpoints.scimGroups,
  scimMe: configData.endpoints.scimMe,
  samlMetadata: configData.endpoints.samlMetadata,
  samlCallback: configData.endpoints.samlCallback,
} as const;

// DynamoDB client for verification tests
const dynamoClient = new DynamoDBClient({ region: AWS_REGION });
export const docClient = DynamoDBDocumentClient.from(dynamoClient);

// Utilities
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function measureTime<T>(fn: () => Promise<T>): Promise<{ result: T; durationMs: number }> {
  const start = performance.now();
  const result = await fn();
  return { result, durationMs: performance.now() - start };
}
