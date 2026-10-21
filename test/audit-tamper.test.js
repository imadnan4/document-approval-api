'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');

const { startHarness } = require('./harness');

async function prepareAuditedDocument(h) {
  const document = await h.createDocument({
    title: 'Audit test',
    body: 'Body',
  });
  await h.approve(document.id, 'officer');
  await h.approve(document.id, 'senior');
  const verification = await h.call('GET', '/audit/verify', {
    token: h.tokens.clerk1,
  });
  assert.equal(verification.status, 200);
  assert.equal(verification.data.valid, true, JSON.stringify(verification.data));
  return document.id;
}

test('a changed audit entry is detected', async (t) => {
  const h = await startHarness();
  t.after(async () => h.stop());
  await prepareAuditedDocument(h);

  await h.withSchemaDb(async (client) => {
    await client.query('DROP TRIGGER audit_entries_no_update ON audit_entries');
    await client.query('UPDATE audit_entries SET details = $1 WHERE seq = 2', [
      '{"forged":true}',
    ]);
  });

  const result = await h.call('GET', '/audit/verify', {
    token: h.tokens.clerk1,
  });
  assert.equal(result.status, 200);
  assert.equal(result.data.valid, false, JSON.stringify(result.data));
  assert.equal(result.data.first_bad_seq, 2);
  assert.ok(
    ['ENTRY_HASH_MISMATCH', 'PREV_HASH_MISMATCH'].includes(result.data.code),
    result.data.code,
  );
});

test('a deleted audit tail is detected', async (t) => {
  const h = await startHarness();
  t.after(async () => h.stop());
  await prepareAuditedDocument(h);

  await h.withSchemaDb(async (client) => {
    const last = await client.query('SELECT MAX(seq) AS last_seq FROM audit_entries');
    const lastSeq = last.rows[0].last_seq;
    await client.query('DROP TRIGGER audit_entries_no_delete ON audit_entries');
    await client.query('DELETE FROM audit_entries WHERE seq = $1', [lastSeq]);
  });

  const result = await h.call('GET', '/audit/verify', {
    token: h.tokens.clerk1,
  });
  assert.equal(result.status, 200);
  assert.equal(result.data.valid, false, JSON.stringify(result.data));
  assert.equal(result.data.code, 'TAIL_TRUNCATED');
});

test('database triggers block audit updates and deletes', async (t) => {
  const h = await startHarness();
  t.after(async () => h.stop());
  await prepareAuditedDocument(h);

  await h.withSchemaDb(async (client) => {
    await assert.rejects(
      client.query("UPDATE audit_entries SET action = 'VIEW' WHERE seq = 1"),
      /append-only/i,
    );
    await assert.rejects(
      client.query('DELETE FROM audit_entries WHERE seq = 1'),
      /append-only/i,
    );
  });

  const result = await h.call('GET', '/audit/verify', {
    token: h.tokens.clerk1,
  });
  assert.equal(result.data.valid, true, JSON.stringify(result.data));
});
