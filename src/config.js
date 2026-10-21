'use strict';

const fs = require('node:fs');
const path = require('node:path');

const DEFAULT_DATABASE_URL =
  'postgresql://helpforce:helpforce@127.0.0.1:5432/helpforce';

function envPath(name, fallback) {
  return path.resolve(process.env[name] || fallback);
}

function baseConfig(dataDir) {
  return {
    dataDir,
    attachmentsDir: envPath('ATTACHMENTS_DIR', path.join(dataDir, 'attachments')),
    auditKeyPath: envPath('AUDIT_KEY_PATH', path.join(dataDir, 'audit.key')),
    auditHeadPath: envPath('AUDIT_HEAD_PATH', path.join(dataDir, 'audit.head.json')),
    databaseUrl: process.env.DATABASE_URL || DEFAULT_DATABASE_URL,
    dbSchema: process.env.DB_SCHEMA || null,
    host: process.env.HOST || '0.0.0.0',
    port: Number.parseInt(process.env.PORT || '8000', 10),
    tokenTtlHours: Number.parseInt(process.env.TOKEN_TTL_HOURS || '12', 10),
  };
}

function loadConfig() {
  const config = baseConfig(envPath('DATA_DIR', path.join('data')));
  ensureDirs(config);
  return config;
}

function testConfig(root, { databaseUrl, dbSchema } = {}) {
  const config = {
    ...baseConfig(root),
    databaseUrl: databaseUrl || process.env.TEST_DATABASE_URL || DEFAULT_DATABASE_URL,
    dbSchema: dbSchema || null,
  };
  ensureDirs(config);
  return config;
}

function ensureDirs(config) {
  for (const dir of [
    config.dataDir,
    config.attachmentsDir,
    path.dirname(config.auditKeyPath),
    path.dirname(config.auditHeadPath),
  ]) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

module.exports = { loadConfig, testConfig, DEFAULT_DATABASE_URL };
