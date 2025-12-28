/**
 * DCR-02: Secret Hash Storage
 *
 * Validates that client secrets are stored as hashes in DynamoDB,
 * not as plaintext. This is critical for database leak protection.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { httpClient } from '../../support/api';
import { createValidDCRPayload } from '../../fixtures';
import { docClient, DYNAMODB_TABLE, ENDPOINTS } from '../../setup';
import { GetCommand } from '@aws-sdk/lib-dynamodb';

describe('DCR-02: Secret Hash Storage', () => {
  const createdClients: Array<{ client_id: string; registration_access_token: string }> = [];

  afterAll(async () => {
    for (const client of createdClients) {
      try {
        await httpClient.delete(`${ENDPOINTS.register}/${client.client_id}`, {
          headers: { Authorization: `Bearer ${client.registration_access_token}` },
        });
      } catch {
        // Ignore cleanup errors
      }
    }
  });

  it('should store clientSecretHash in DB, NOT plaintext secret', async () => {
    // Arrange
    const payload = createValidDCRPayload();

    // Act - Create client
    const response = await httpClient.postJson<{
      client_id: string;
      client_secret: string;
      registration_access_token: string;
    }>(ENDPOINTS.register, payload);

    expect(response.status).toBe(201);
    const { client_id, client_secret, registration_access_token } = response.data;
    createdClients.push({ client_id, registration_access_token });

    // Verify in DynamoDB
    const dbResult = await docClient.send(
      new GetCommand({
        TableName: DYNAMODB_TABLE,
        Key: {
          PK: `CLIENT#${client_id}`,
          SK: 'CONFIG',
        },
      })
    );

    // Assert
    expect(dbResult.Item).toBeDefined();

    // The plaintext secret should NOT be stored
    expect(dbResult.Item!.client_secret).toBeUndefined();
    expect(dbResult.Item!.secret).toBeUndefined();

    // A hash should be stored instead (field name is clientSecretHash per implementation)
    expect(dbResult.Item!.clientSecretHash).toBeDefined();
    expect(typeof dbResult.Item!.clientSecretHash).toBe('string');

    // The hash should NOT equal the plaintext secret
    expect(dbResult.Item!.clientSecretHash).not.toBe(client_secret);

    // Hash should look like a proper hash (reasonable length)
    expect(dbResult.Item!.clientSecretHash.length).toBeGreaterThan(32);
  });
});
