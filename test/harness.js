'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Pool } = require('pg');

const { DEFAULT_DATABASE_URL, testConfig } = require('../src/config');
const { createServer } = require('../src/server');

const USERS = {
  clerk1: 'clerk1-demo-pass',
  clerk2: 'clerk2-demo-pass',
  officer: 'officer-demo-pass',
  senior: 'senior-demo-pass',
};

const PDF = Buffer.from(
  '%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n',
  'utf8',
);

function testDsn() {
  return (
    process.env.TEST_DATABASE_URL ||
    process.env.DATABASE_URL ||
    DEFAULT_DATABASE_URL
  );
}

async function startHarness() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'helpforce-js-'));
  const schema = `test_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;
  const dsn = testDsn();

  const admin = new Pool({ connectionString: dsn });
  try {
    await admin.query(`CREATE SCHEMA "${schema}"`);
  } finally {
    await admin.end();
  }

  const config = testConfig(root, { databaseUrl: dsn, dbSchema: schema });
  const server = await createServer(config);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;

  async function call(method, urlPath, { token, body, raw = false } = {}) {
    const headers = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    let payload;
    if (body !== undefined) {
      payload = JSON.stringify(body);
      headers['Content-Type'] = 'application/json';
    }
    const response = await fetch(base + urlPath, { method, headers, body: payload });
    const buffer = Buffer.from(await response.arrayBuffer());
    const contentType = response.headers.get('content-type') || '';
    let data = buffer;
    if (!raw && contentType.includes('application/json') && buffer.length) {
      data = JSON.parse(buffer.toString('utf8'));
    }
    return { status: response.status, headers: response.headers, data, buffer };
  }

  const harness = {
    config,
    call,
    tokens: {},
    async login(username, password) {
      const result = await call('POST', '/auth/login', {
        body: { username, password },
      });
      if (result.status !== 200) {
        throw new Error(`login failed: ${JSON.stringify(result.data)}`);
      }
      return result.data.token;
    },
    async createDocument({
      token = harness.tokens.clerk1,
      title = 'Policy update',
      body = 'The body of the document.',
      attachment = null,
    } = {}) {
      const payload = { title, body };
      if (attachment) {
        payload.attachment = {
          filename: 'policy.pdf',
          content_base64: attachment.toString('base64'),
        };
      }
      const result = await call('POST', '/documents', { token, body: payload });
      if (result.status !== 201) {
        throw new Error(`create failed: ${JSON.stringify(result.data)}`);
      }
      return result.data;
    },
    async approve(documentId, role) {
      const result = await call('POST', `/documents/${documentId}/approve`, {
        token: harness.tokens[role],
      });
      if (result.status !== 200) {
        throw new Error(`approve failed: ${JSON.stringify(result.data)}`);
      }
      return result.data;
    },
    async approveToFinal(documentId) {
      await harness.approve(documentId, 'officer');
      return harness.approve(documentId, 'senior');
    },
    async reject(documentId, role, reason) {
      const result = await call('POST', `/documents/${documentId}/reject`, {
        token: harness.tokens[role],
        body: { reason },
      });
      if (result.status !== 200) {
        throw new Error(`reject failed: ${JSON.stringify(result.data)}`);
      }
      return result.data;
    },
    // Direct SQL as an attacker with database credentials, in this schema.
    async withSchemaDb(fn) {
      const pool = new Pool({ connectionString: dsn });
      const client = await pool.connect();
      try {
        await client.query(`SET search_path TO "${schema}"`);
        return await fn(client);
      } finally {
        client.release();
        await pool.end();
      }
    },
    async stop() {
      await new Promise((resolve) => server.close(resolve));
      await server.service.close();
      const drop = new Pool({ connectionString: dsn });
      try {
        await drop.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
      } finally {
        await drop.end();
      }
      fs.rmSync(root, { recursive: true, force: true });
    },
  };

  for (const [username, password] of Object.entries(USERS)) {
    harness.tokens[username] = await harness.login(username, password);
  }
  return harness;
}

module.exports = { startHarness, PDF };
