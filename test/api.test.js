'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { after, before, describe, test } = require('node:test');

const { contentDigest } = require('../src/security');
const { PDF, startHarness } = require('./harness');

function assertError(result, status, code) {
  assert.equal(result.status, status, JSON.stringify(result.data));
  assert.equal(result.data.error.code, code, JSON.stringify(result.data));
}

describe('document workflow API', { concurrency: false }, () => {
  let h;

  before(async () => {
    h = await startHarness();
  });

  after(async () => {
    await h.stop();
  });

  test('every non-login request is authenticated', async () => {
    let result = await h.call('GET', '/documents');
    assertError(result, 401, 'UNAUTHENTICATED');
    result = await h.call('GET', '/documents', { token: 'not-a-token' });
    assertError(result, 401, 'UNAUTHENTICATED');
  });

  test('login, logout and current user', async () => {
    let result = await h.call('GET', '/me', { token: h.tokens.clerk1 });
    assert.equal(result.status, 200);
    assert.equal(result.data.user.role, 'CLERK');

    const token = await h.login('officer', 'officer-demo-pass');
    result = await h.call('POST', '/auth/logout', { token });
    assert.equal(result.status, 200);
    result = await h.call('GET', '/me', { token });
    assertError(result, 401, 'UNAUTHENTICATED');

    result = await h.call('POST', '/auth/login', {
      body: { username: 'officer', password: 'wrong' },
    });
    assertError(result, 401, 'INVALID_CREDENTIALS');
  });

  test('a clerk cannot approve or reject', async () => {
    const document = await h.createDocument();
    let result = await h.call('POST', `/documents/${document.id}/approve`, {
      token: h.tokens.clerk1,
    });
    assertError(result, 403, 'FORBIDDEN_ROLE');
    result = await h.call('POST', `/documents/${document.id}/reject`, {
      token: h.tokens.clerk1,
      body: { reason: 'no' },
    });
    assertError(result, 403, 'FORBIDDEN_ROLE');
  });

  test('an officer cannot act on an approved document', async () => {
    const document = await h.createDocument();
    await h.approveToFinal(document.id);
    let result = await h.call('POST', `/documents/${document.id}/approve`, {
      token: h.tokens.officer,
    });
    assertError(result, 409, 'DOCUMENT_LOCKED');
    result = await h.call('POST', `/documents/${document.id}/reject`, {
      token: h.tokens.officer,
      body: { reason: 'late' },
    });
    assertError(result, 409, 'DOCUMENT_LOCKED');
  });

  test('officers cannot act out of turn', async () => {
    const document = await h.createDocument();
    let result = await h.call('POST', `/documents/${document.id}/approve`, {
      token: h.tokens.senior,
    });
    assertError(result, 409, 'NOT_AT_YOUR_LEVEL');

    await h.approve(document.id, 'officer');
    result = await h.call('POST', `/documents/${document.id}/approve`, {
      token: h.tokens.officer,
    });
    assertError(result, 409, 'NOT_AT_YOUR_LEVEL');
  });

  test('a clerk cannot access another clerk\'s document', async () => {
    const document = await h.createDocument();
    const url = `/documents/${document.id}`;
    for (const [method, body] of [
      ['GET', undefined],
      ['PATCH', { title: 'stolen' }],
      ['DELETE', undefined],
    ]) {
      const result = await h.call(method, url, {
        token: h.tokens.clerk2,
        body,
      });
      assertError(result, 403, 'FORBIDDEN_NOT_OWNER');
    }
    let result = await h.call('GET', `${url}/audit`, {
      token: h.tokens.clerk2,
    });
    assertError(result, 403, 'FORBIDDEN_NOT_OWNER');

    result = await h.call('GET', '/documents', { token: h.tokens.clerk2 });
    assert.equal(result.status, 200);
    assert.ok(
      !result.data.documents.some((entry) => entry.id === document.id),
      'other clerk document should not be listed',
    );
  });

  test('full approval path locks the document', async () => {
    let document = await h.createDocument();
    assert.equal(document.status, 'PENDING_OFFICER');
    document = await h.approve(document.id, 'officer');
    assert.equal(document.status, 'PENDING_SENIOR_OFFICER');
    document = await h.approve(document.id, 'senior');
    assert.equal(document.status, 'APPROVED');
    assert.ok(document.approved_at);

    const url = `/documents/${document.id}`;
    let result = await h.call('PATCH', url, {
      token: h.tokens.clerk1,
      body: { title: 'changed' },
    });
    assertError(result, 409, 'DOCUMENT_LOCKED');
    result = await h.call('POST', `${url}/submit`, { token: h.tokens.clerk1 });
    assertError(result, 409, 'DOCUMENT_LOCKED');
    result = await h.call('DELETE', url, { token: h.tokens.clerk1 });
    assertError(result, 409, 'DOCUMENT_LOCKED');
    result = await h.call('PATCH', url, {
      token: h.tokens.officer,
      body: { title: 'changed' },
    });
    assertError(result, 409, 'DOCUMENT_LOCKED');

    result = await h.call('GET', `${url}/integrity`, {
      token: h.tokens.clerk1,
    });
    assert.equal(result.status, 200, JSON.stringify(result.data));
    assert.equal(result.data.valid, true);
    assert.equal(result.data.content_matches, true);
  });

  test('rejection, edit and resubmission', async () => {
    const document = await h.createDocument();
    let result = await h.call('POST', `/documents/${document.id}/reject`, {
      token: h.tokens.officer,
      body: {},
    });
    assertError(result, 400, 'VALIDATION_ERROR');

    const rejected = await h.reject(document.id, 'officer', 'Add the appendix');
    assert.equal(rejected.status, 'RETURNED');
    assert.equal(rejected.last_rejection.reason, 'Add the appendix');

    result = await h.call('PATCH', `/documents/${document.id}`, {
      token: h.tokens.clerk2,
      body: { title: 'hijack' },
    });
    assertError(result, 403, 'FORBIDDEN_NOT_OWNER');

    result = await h.call('PATCH', `/documents/${document.id}`, {
      token: h.tokens.clerk1,
      body: { title: 'Policy update with appendix' },
    });
    assert.equal(result.status, 200, JSON.stringify(result.data));
    assert.equal(result.data.status, 'RETURNED');

    result = await h.call('POST', `/documents/${document.id}/submit`, {
      token: h.tokens.clerk1,
    });
    assert.equal(result.status, 200, JSON.stringify(result.data));
    assert.equal(result.data.status, 'PENDING_OFFICER');
    assert.equal(result.data.revision, 2);
    assert.equal(result.data.last_rejection, null);

    result = await h.call('GET', `/documents/${document.id}/audit`, {
      token: h.tokens.clerk1,
    });
    assert.equal(result.status, 200, JSON.stringify(result.data));
    const actions = result.data.entries.map((entry) => entry.action);
    for (const action of ['CREATE', 'SUBMIT', 'REJECT', 'EDIT', 'SUBMIT']) {
      assert.ok(actions.includes(action), `missing ${action} in ${actions}`);
    }
    assert.ok(
      result.data.entries.some(
        (entry) =>
          entry.action === 'REJECT' &&
          entry.details.reason === 'Add the appendix',
      ),
    );
  });

  test('delete rules: returned is allowed, approved is locked', async () => {
    let document = await h.createDocument();
    await h.reject(document.id, 'officer', 'Not needed');
    let result = await h.call('DELETE', `/documents/${document.id}`, {
      token: h.tokens.clerk1,
    });
    assert.equal(result.status, 200, JSON.stringify(result.data));
    assert.equal(result.data.status, 'DELETED');
    result = await h.call('GET', '/documents', { token: h.tokens.clerk1 });
    assert.ok(!result.data.documents.some((entry) => entry.id === document.id));

    document = await h.createDocument();
    await h.approveToFinal(document.id);
    result = await h.call('DELETE', `/documents/${document.id}`, {
      token: h.tokens.clerk1,
    });
    assertError(result, 409, 'DOCUMENT_LOCKED');
  });

  test('validation errors are explicit', async () => {
    let result = await h.call('POST', '/documents', {
      token: h.tokens.clerk1,
      body: { title: 'x' },
    });
    assertError(result, 400, 'VALIDATION_ERROR');
    result = await h.call('POST', '/documents', {
      token: h.tokens.clerk1,
      body: {
        title: 'x',
        body: 'y',
        attachment: { filename: 'x.pdf', content_base64: '!!!' },
      },
    });
    assertError(result, 400, 'INVALID_ATTACHMENT');
    result = await h.call('POST', '/documents', {
      token: h.tokens.clerk1,
      body: {
        title: 'x',
        body: 'y',
        attachment: {
          filename: 'x.txt',
          content_base64: Buffer.from('%PDF-').toString('base64'),
        },
      },
    });
    assertError(result, 400, 'INVALID_ATTACHMENT');
  });

  test('attachment download and integrity tamper detection', async () => {
    const document = await h.createDocument({ attachment: PDF });
    await h.approveToFinal(document.id);
    const url = `/documents/${document.id}`;

    let result = await h.call('GET', `${url}/attachment`, {
      token: h.tokens.clerk1,
      raw: true,
    });
    assert.equal(result.status, 200);
    assert.deepEqual(result.data, PDF);
    assert.equal(result.headers.get('content-type'), 'application/pdf');
    assert.equal(result.headers.get('x-content-sha256').length, 64);

    result = await h.call('GET', `${url}/integrity`, {
      token: h.tokens.clerk1,
    });
    assert.equal(result.status, 200);
    assert.equal(result.data.valid, true);
    assert.equal(result.data.attachment_matches, true);

    const attachmentPath = path.join(
      h.config.attachmentsDir,
      `${document.id}.pdf`,
    );
    fs.writeFileSync(attachmentPath, Buffer.concat([PDF, Buffer.from('tampered')]));
    result = await h.call('GET', `${url}/integrity`, {
      token: h.tokens.clerk1,
    });
    assert.equal(result.status, 200);
    assert.equal(result.data.valid, false);
    assert.equal(result.data.attachment_matches, false);
  });

  test('content changed directly in the database is detected', async () => {
    const document = await h.createDocument();
    await h.approveToFinal(document.id);
    await h.withSchemaDb(async (client) => {
      await client.query('UPDATE documents SET body = $1 WHERE id = $2', [
        'Changed directly in SQL',
        document.id,
      ]);
    });
    const result = await h.call('GET', `/documents/${document.id}/integrity`, {
      token: h.tokens.clerk1,
    });
    assert.equal(result.status, 200);
    assert.equal(result.data.valid, false);
    assert.equal(result.data.content_matches, false);
  });

  test('tampered approval hashes are detected against the audit snapshot', async () => {
    const document = await h.createDocument();
    await h.approveToFinal(document.id);
    const newBody = 'Changed together with the stored hashes';
    const newDigest = contentDigest(document.title, newBody);
    await h.withSchemaDb(async (client) => {
      await client.query(
        `UPDATE documents SET
           body = $1, content_sha256 = $2, approved_content_sha256 = $3
         WHERE id = $4`,
        [newBody, newDigest, newDigest, document.id],
      );
    });
    const result = await h.call('GET', `/documents/${document.id}/integrity`, {
      token: h.tokens.clerk1,
    });
    assert.equal(result.status, 200);
    assert.equal(result.data.content_matches, true);
    assert.equal(result.data.snapshot_matches_audit, false);
    assert.equal(result.data.valid, false);
  });

  test('a corrupt attachment blocks final approval', async () => {
    const document = await h.createDocument({ attachment: PDF });
    const attachmentPath = path.join(
      h.config.attachmentsDir,
      `${document.id}.pdf`,
    );
    fs.writeFileSync(attachmentPath, Buffer.concat([PDF, Buffer.from('corrupt')]));
    await h.approve(document.id, 'officer');
    const result = await h.call('POST', `/documents/${document.id}/approve`, {
      token: h.tokens.senior,
    });
    assertError(result, 409, 'ATTACHMENT_INTEGRITY_ERROR');
  });

  test('audit history and verification', async () => {
    const document = await h.createDocument();
    let result = await h.call('GET', '/documents', { token: h.tokens.clerk1 });
    assert.equal(result.status, 200);
    result = await h.call('GET', `/documents/${document.id}`, {
      token: h.tokens.clerk1,
    });
    assert.equal(result.status, 200);
    result = await h.call('GET', `/documents/${document.id}/audit`, {
      token: h.tokens.clerk1,
    });
    assert.equal(result.status, 200);
    const actions = result.data.entries.map((entry) => entry.action);
    assert.deepEqual(actions.slice(0, 2), ['CREATE', 'SUBMIT']);
    assert.ok(
      result.data.entries.some(
        (entry) => entry.action === 'VIEW' && entry.details.scope === 'list',
      ),
    );
    assert.ok(actions.includes('VIEW'));

    result = await h.call('GET', '/audit/verify', { token: h.tokens.senior });
    assert.equal(result.status, 200);
    assert.equal(result.data.valid, true, JSON.stringify(result.data));
    assert.equal(result.data.anchored, true);
  });

  test('two concurrent officer approvals cannot both succeed', async () => {
    const document = await h.createDocument();
    const results = await Promise.all([
      h.call('POST', `/documents/${document.id}/approve`, {
        token: h.tokens.officer,
      }),
      h.call('POST', `/documents/${document.id}/approve`, {
        token: h.tokens.officer,
      }),
    ]);
    const statuses = results.map((result) => result.status).sort();
    assert.deepEqual(statuses, [200, 409]);
    const history = await h.call('GET', `/documents/${document.id}/audit`, {
      token: h.tokens.clerk1,
    });
    const approvals = history.data.entries.filter(
      (entry) => entry.action === 'APPROVE',
    );
    assert.equal(approvals.length, 1);
  });
});
