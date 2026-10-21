'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');

const PBKDF2_ITERATIONS = 210000;
const GENESIS_HASH = '0'.repeat(64);

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(',')}]`;
  }
  const keys = Object.keys(value).sort();
  return `{${keys
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(',')}}`;
}

function sha256Bytes(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function sha256Text(value) {
  return sha256Bytes(Buffer.from(value, 'utf8'));
}

function sha256File(filePath) {
  return sha256Bytes(fs.readFileSync(filePath));
}

function contentDigest(title, body) {
  return sha256Text(canonicalJson({ body, title }));
}

function utcNow() {
  return new Date().toISOString();
}

function isoAfter(hours) {
  return new Date(Date.now() + hours * 3600 * 1000).toISOString();
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const derived = crypto.pbkdf2Sync(
    Buffer.from(password, 'utf8'),
    salt,
    PBKDF2_ITERATIONS,
    32,
    'sha256',
  );
  return `pbkdf2_sha256$${PBKDF2_ITERATIONS}$${salt.toString('base64')}$${derived.toString('base64')}`;
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function verifyPassword(password, stored) {
  try {
    const [algorithm, iterations, saltB64, digestB64] = stored.split('$');
    if (algorithm !== 'pbkdf2_sha256') return false;
    const salt = Buffer.from(saltB64, 'base64');
    const expected = Buffer.from(digestB64, 'base64');
    const actual = crypto.pbkdf2Sync(
      Buffer.from(password, 'utf8'),
      salt,
      Number.parseInt(iterations, 10),
      expected.length,
      'sha256',
    );
    return crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

function newSessionToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function tokenDigest(token) {
  return sha256Text(token);
}

module.exports = {
  GENESIS_HASH,
  canonicalJson,
  sha256Bytes,
  sha256File,
  contentDigest,
  utcNow,
  isoAfter,
  hashPassword,
  verifyPassword,
  safeEqual,
  newSessionToken,
  tokenDigest,
};
