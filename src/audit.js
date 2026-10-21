'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const {
  GENESIS_HASH,
  canonicalJson,
  safeEqual,
  utcNow,
} = require('./security');

class AnchorError extends Error {}

function entryPayload(row) {
  return {
    seq: row.seq,
    document_id: row.document_id,
    actor_id: row.actor_id,
    actor_role: row.actor_role,
    action: row.action,
    status_before: row.status_before,
    status_after: row.status_after,
    details: row.details,
    created_at: row.created_at,
    prev_hash: row.prev_hash,
  };
}

function entryHash(key, payload) {
  return crypto
    .createHmac('sha256', key)
    .update(canonicalJson(payload), 'utf8')
    .digest('hex');
}

async function appendEntry(
  db,
  key,
  {
    documentId,
    actorId,
    actorRole,
    action,
    statusBefore,
    statusAfter,
    details,
  },
) {
  const row = await db.one(
    'SELECT seq, entry_hash FROM audit_entries ORDER BY seq DESC LIMIT 1',
  );
  const seq = row ? Number(row.seq) + 1 : 1;
  const prevHash = row ? row.entry_hash : GENESIS_HASH;
  const detailsJson = canonicalJson(details || {});
  const payload = {
    seq,
    document_id: documentId,
    actor_id: actorId,
    actor_role: actorRole,
    action,
    status_before: statusBefore,
    status_after: statusAfter,
    details: detailsJson,
    created_at: utcNow(),
    prev_hash: prevHash,
  };
  await db.run(
    `INSERT INTO audit_entries
       (seq, document_id, actor_id, actor_role, action, status_before,
        status_after, details, created_at, prev_hash, entry_hash)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      seq,
      documentId,
      actorId,
      actorRole,
      action,
      statusBefore,
      statusAfter,
      detailsJson,
      payload.created_at,
      prevHash,
      entryHash(key, payload),
    ],
  );
  return seq;
}

function serializeEntry(row) {
  return {
    seq: row.seq,
    document_id: row.document_id,
    actor: { id: row.actor_id, role: row.actor_role },
    action: row.action,
    status_before: row.status_before,
    status_after: row.status_after,
    details: JSON.parse(row.details),
    created_at: row.created_at,
    prev_hash: row.prev_hash,
    entry_hash: row.entry_hash,
  };
}

function readAnchor(filePath) {
  if (!fs.existsSync(filePath)) return null;
  try {
    const value = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const seq = Number.parseInt(value.seq, 10);
    const digest = String(value.entry_hash);
    if (!Number.isInteger(seq) || seq < 0 || digest.length !== 64) {
      throw new Error('invalid values');
    }
    return { seq, entry_hash: digest, updated_at: value.updated_at };
  } catch (error) {
    throw new AnchorError(`checkpoint file is invalid: ${error.message}`);
  }
}

function writeAnchor(filePath, seq, digest) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const temp = path.join(
    path.dirname(filePath),
    `.audit-head-${process.pid}-${crypto.randomBytes(6).toString('hex')}`,
  );
  try {
    const fd = fs.openSync(temp, 'wx', 0o600);
    try {
      fs.writeSync(
        fd,
        canonicalJson({ seq, entry_hash: digest, updated_at: utcNow() }),
        null,
        'utf8',
      );
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(temp, filePath);
  } finally {
    try {
      fs.unlinkSync(temp);
    } catch {
      // Already renamed or never created.
    }
  }
}

async function verifyChain(db, key, anchor) {
  const rows = await db.all('SELECT * FROM audit_entries ORDER BY seq ASC');
  let previous = GENESIS_HASH;
  let expectedSeq = 1;
  let headSeq = 0;
  let headHash = GENESIS_HASH;
  let anchorEntryHash = null;

  for (const row of rows) {
    const seq = Number(row.seq);
    if (seq !== expectedSeq) {
      return {
        valid: false,
        code: 'SEQUENCE_GAP',
        message: `expected audit seq ${expectedSeq}, found ${seq}`,
        first_bad_seq: seq,
        entries_checked: expectedSeq - 1,
        head_seq: headSeq,
      };
    }
    if (!safeEqual(row.prev_hash, previous)) {
      return {
        valid: false,
        code: 'PREV_HASH_MISMATCH',
        message: 'entry does not link to the previous entry',
        first_bad_seq: seq,
        entries_checked: expectedSeq - 1,
        head_seq: headSeq,
      };
    }
    const expectedHash = entryHash(key, entryPayload(row));
    if (!safeEqual(row.entry_hash, expectedHash)) {
      return {
        valid: false,
        code: 'ENTRY_HASH_MISMATCH',
        message: 'entry contents do not match their HMAC',
        first_bad_seq: seq,
        entries_checked: expectedSeq - 1,
        head_seq: headSeq,
      };
    }
    if (anchor && seq === anchor.seq) anchorEntryHash = row.entry_hash;
    previous = row.entry_hash;
    headSeq = seq;
    headHash = row.entry_hash;
    expectedSeq += 1;
  }

  const result = {
    valid: true,
    code: 'OK',
    message: 'audit chain is intact',
    entries_checked: rows.length,
    head_seq: headSeq,
    head_hash: headHash,
    anchored: anchor !== null,
  };

  if (!anchor) {
    result.message =
      'audit chain is intact; no local checkpoint exists, so tail truncation cannot be ruled out';
    return result;
  }

  result.anchor_seq = anchor.seq;
  if (anchor.seq > headSeq) {
    Object.assign(result, {
      valid: false,
      code: 'TAIL_TRUNCATED',
      message:
        'checkpoint is ahead of the database; audit entries have been removed or the database was rolled back',
      first_bad_seq: headSeq + 1,
    });
  } else if (
    anchor.seq > 0 &&
    !(anchorEntryHash && safeEqual(anchorEntryHash, anchor.entry_hash))
  ) {
    Object.assign(result, {
      valid: false,
      code: 'CHECKPOINT_MISMATCH',
      message: 'checkpoint does not match the database entry at that seq',
      first_bad_seq: anchor.seq,
    });
  }
  return result;
}

module.exports = {
  AnchorError,
  appendEntry,
  serializeEntry,
  readAnchor,
  writeAnchor,
  verifyChain,
};
