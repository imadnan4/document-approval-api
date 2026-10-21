#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const { parseArgs } = require('node:util');

const { AnchorError, readAnchor, verifyChain } = require('./audit');
const { loadConfig } = require('./config');
const { closeDb, createDb } = require('./db');
const { loadOrCreateAuditKey } = require('./service');

const config = loadConfig();
const { values } = parseArgs({
  options: {
    dsn: { type: 'string', default: config.databaseUrl },
    schema: { type: 'string', default: config.dbSchema || '' },
    key: { type: 'string', default: config.auditKeyPath },
    head: { type: 'string', default: config.auditHeadPath },
  },
});

if (!fs.existsSync(values.key) && !process.env.AUDIT_HMAC_KEY) {
  console.error(JSON.stringify({ valid: false, code: 'AUDIT_KEY_NOT_FOUND' }));
  process.exit(2);
}

const key = loadOrCreateAuditKey(values.key);
let anchor;
try {
  anchor = readAnchor(values.head);
} catch (error) {
  console.log(
    JSON.stringify({
      valid: false,
      code: 'CHECKPOINT_INVALID',
      message: error instanceof AnchorError ? error.message : String(error),
    }),
  );
  process.exit(1);
}

async function main() {
  const db = createDb({ ...config, databaseUrl: values.dsn, dbSchema: values.schema || null });
  let result;
  try {
    result = await verifyChain(db, key, anchor);
  } catch (error) {
    console.error(JSON.stringify({ valid: false, code: 'DATABASE_ERROR', message: error.message }));
    process.exitCode = 2;
    return;
  } finally {
    await closeDb(db);
  }
  console.log(JSON.stringify(result, null, 2));
  process.exitCode = result.valid ? 0 : 1;
}

main();
