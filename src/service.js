'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const {
  appendEntry,
  readAnchor,
  serializeEntry,
  verifyChain,
  writeAnchor,
} = require('./audit');
const { closeDb, createDb, initDatabase, withTransaction } = require('./db');
const { ApiError, badRequest, conflict, forbidden, notFound } = require('./errors');
const {
  GENESIS_HASH,
  contentDigest,
  isoAfter,
  newSessionToken,
  sha256Bytes,
  sha256File,
  tokenDigest,
  utcNow,
  verifyPassword,
} = require('./security');
const { seedUsers } = require('./seed');

const CLERK = 'CLERK';
const OFFICER = 'OFFICER';
const SENIOR_OFFICER = 'SENIOR_OFFICER';

const PENDING_OFFICER = 'PENDING_OFFICER';
const PENDING_SENIOR_OFFICER = 'PENDING_SENIOR_OFFICER';
const RETURNED = 'RETURNED';
const APPROVED = 'APPROVED';
const DELETED = 'DELETED';
const DRAFT = 'DRAFT';

const QUEUE_FOR_ROLE = {
  [OFFICER]: PENDING_OFFICER,
  [SENIOR_OFFICER]: PENDING_SENIOR_OFFICER,
};

const MAX_TITLE_LENGTH = 300;
const MAX_BODY_LENGTH = 200000;
const MAX_REASON_LENGTH = 5000;
const MAX_FILENAME_LENGTH = 255;
const MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024;

function loadOrCreateAuditKey(keyPath) {
  const envKey = process.env.AUDIT_HMAC_KEY;
  if (envKey) {
    if (!/^[0-9a-fA-F]+$/.test(envKey) || envKey.length < 64) {
      throw new Error('AUDIT_HMAC_KEY must be at least 32 hex-encoded bytes');
    }
    return Buffer.from(envKey, 'hex');
  }
  if (fs.existsSync(keyPath)) {
    const key = fs.readFileSync(keyPath);
    if (key.length < 32) throw new Error(`audit key at ${keyPath} is too short`);
    return key;
  }
  fs.mkdirSync(path.dirname(keyPath), { recursive: true });
  const key = crypto.randomBytes(32);
  try {
    fs.writeFileSync(keyPath, key, { mode: 0o600, flag: 'wx' });
    return key;
  } catch (error) {
    if (error.code === 'EEXIST') return fs.readFileSync(keyPath);
    throw error;
  }
}

function decodeBase64Strict(value) {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) {
    throw new Error('invalid base64');
  }
  const data = Buffer.from(value, 'base64');
  if (data.toString('base64') !== value) throw new Error('invalid base64');
  return data;
}

class WorkflowService {
  constructor(config) {
    this.config = config;
    this.key = loadOrCreateAuditKey(config.auditKeyPath);
    this.db = createDb(config);
  }

  async initialize() {
    await initDatabase(this.db);
    await withTransaction(this.db, async (tx) => {
      await seedUsers(tx);
    });
    let anchor;
    try {
      anchor = readAnchor(this.config.auditHeadPath);
    } catch (error) {
      console.error(`audit checkpoint is unreadable: ${error.message}`);
      return;
    }
    const result = await verifyChain(this.db, this.key, anchor);
    if (!result.valid) {
      console.error('audit verification failed at startup:', result);
      return;
    }
    await this.advanceAnchor(this.db);
  }

  async close() {
    await closeDb(this.db);
  }

  async advanceAnchor(db) {
    const row = await db.one(
      'SELECT seq, entry_hash FROM audit_entries ORDER BY seq DESC LIMIT 1',
    );
    const seq = row ? Number(row.seq) : 0;
    const digest = row ? row.entry_hash : GENESIS_HASH;
    let current;
    try {
      current = readAnchor(this.config.auditHeadPath);
    } catch (error) {
      console.error(`not advancing unreadable audit checkpoint: ${error.message}`);
      return;
    }
    if (current && current.seq > seq) return;
    try {
      writeAnchor(this.config.auditHeadPath, seq, digest);
    } catch (error) {
      console.error(`could not write audit checkpoint: ${error.message}`);
    }
  }

  async login(username, password) {
    if (typeof username !== 'string' || typeof password !== 'string') {
      throw badRequest('VALIDATION_ERROR', 'username and password are required');
    }
    const row = await this.db.one('SELECT * FROM users WHERE username = ?', [
      username,
    ]);
    if (!row || !verifyPassword(password, row.password_hash)) {
      throw new ApiError(
        401,
        'INVALID_CREDENTIALS',
        'username or password is incorrect',
      );
    }
    const now = utcNow();
    const token = newSessionToken();
    const expiresAt = isoAfter(this.config.tokenTtlHours);
    await withTransaction(this.db, async (tx) => {
      await tx.run('DELETE FROM sessions WHERE expires_at <= ?', [now]);
      await tx.run(
        `INSERT INTO sessions (token_hash, user_id, created_at, expires_at)
         VALUES (?, ?, ?, ?)`,
        [tokenDigest(token), row.id, now, expiresAt],
      );
    });
    return {
      token,
      token_type: 'Bearer',
      expires_at: expiresAt,
      user: this.publicUser(row),
    };
  }

  async logout(token) {
    await this.db.run('DELETE FROM sessions WHERE token_hash = ?', [
      tokenDigest(token),
    ]);
  }

  async authenticate(token) {
    const row = await this.db.one(
      `SELECT u.* FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = ?`,
      [tokenDigest(token)],
    );
    if (!row) {
      throw new ApiError(401, 'UNAUTHENTICATED', 'a valid bearer token is required');
    }
    const session = await this.db.one(
      'SELECT expires_at FROM sessions WHERE token_hash = ?',
      [tokenDigest(token)],
    );
    if (!session || session.expires_at <= utcNow()) {
      await this.db.run('DELETE FROM sessions WHERE token_hash = ?', [
        tokenDigest(token),
      ]);
      throw new ApiError(401, 'UNAUTHENTICATED', 'the session has expired');
    }
    return this.publicUser(row);
  }

  getMe(user) {
    return { user };
  }

  publicUser(row) {
    return {
      id: row.id,
      username: row.username,
      display_name: row.display_name,
      role: row.role,
    };
  }

  async userBrief(db, userId) {
    if (!userId) return null;
    const row = await db.one(
      'SELECT id, username, display_name, role FROM users WHERE id = ?',
      [userId],
    );
    return row ? this.publicUser(row) : null;
  }

  async serializeDocument(db, row) {
    const attachment = row.attachment_stored_name
      ? {
          filename: row.attachment_filename,
          size: row.attachment_size,
          sha256: row.attachment_sha256,
        }
      : null;
    const rejection =
      row.last_rejection_reason !== null
        ? {
            reason: row.last_rejection_reason,
            at: row.last_rejected_at,
            by: await this.userBrief(db, row.last_rejected_by),
          }
        : null;
    return {
      id: row.id,
      title: row.title,
      body: row.body,
      status: row.status,
      revision: row.revision,
      content_sha256: row.content_sha256,
      created_at: row.created_at,
      updated_at: row.updated_at,
      created_by: await this.userBrief(db, row.created_by),
      attachment,
      last_rejection: rejection,
      approved_at: row.approved_at,
      approved_by: await this.userBrief(db, row.approved_by),
      deleted_at: row.deleted_at,
    };
  }

  requireDict(payload) {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      throw badRequest('VALIDATION_ERROR', 'request body must be a JSON object');
    }
    return payload;
  }

  text(payload, field, { maxLength, required = false, fallback = null }) {
    if (!Object.prototype.hasOwnProperty.call(payload, field)) {
      if (required) throw badRequest('VALIDATION_ERROR', `${field} is required`);
      return fallback;
    }
    let value = payload[field];
    if (typeof value !== 'string') {
      throw badRequest('VALIDATION_ERROR', `${field} must be a string`);
    }
    if (field !== 'body') value = value.trim();
    if (field !== 'body' && !value) {
      throw badRequest('VALIDATION_ERROR', `${field} must not be empty`);
    }
    if (value.length > maxLength) {
      throw badRequest(
        'VALIDATION_ERROR',
        `${field} must be at most ${maxLength} characters`,
      );
    }
    return value;
  }

  parseAttachment(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw badRequest(
        'INVALID_ATTACHMENT',
        'attachment must be an object with filename and content_base64',
      );
    }
    let filename = value.filename;
    let content = value.content_base64;
    if (typeof filename !== 'string' || !filename.trim()) {
      throw badRequest('INVALID_ATTACHMENT', 'attachment.filename is required');
    }
    filename = filename.trim().replace(/\\/g, '/').split('/').pop();
    if (filename.length > MAX_FILENAME_LENGTH) {
      throw badRequest('INVALID_ATTACHMENT', 'attachment filename is too long');
    }
    if (/[\x00-\x1f\x7f"\\]/.test(filename)) {
      throw badRequest(
        'INVALID_ATTACHMENT',
        'attachment filename contains unsafe characters',
      );
    }
    if (!filename.toLowerCase().endsWith('.pdf')) {
      throw badRequest('INVALID_ATTACHMENT', 'only PDF attachments are accepted');
    }
    if (typeof content !== 'string' || !content) {
      throw badRequest(
        'INVALID_ATTACHMENT',
        'attachment.content_base64 is required',
      );
    }
    if (content.startsWith('data:') && content.includes(',')) {
      content = content.split(',', 2)[1];
    }
    let data;
    try {
      data = decodeBase64Strict(content);
    } catch {
      throw badRequest('INVALID_ATTACHMENT', 'attachment content is not valid base64');
    }
    if (!data.subarray(0, 5).equals(Buffer.from('%PDF-'))) {
      throw badRequest('INVALID_ATTACHMENT', 'attachment is not a PDF file');
    }
    if (data.length > MAX_ATTACHMENT_BYTES) {
      throw badRequest(
        'INVALID_ATTACHMENT',
        `attachment must be at most ${MAX_ATTACHMENT_BYTES} bytes`,
      );
    }
    return {
      filename,
      data,
      sha256: sha256Bytes(data),
      size: data.length,
    };
  }

  async getDocumentRow(db, documentId) {
    const row = await db.one('SELECT * FROM documents WHERE id = ?', [documentId]);
    if (!row) throw notFound('DOCUMENT_NOT_FOUND', 'document not found');
    return row;
  }

  async canView(db, user, doc) {
    if (user.role === CLERK) return doc.created_by === user.id;
    if (doc.status === DELETED) return false;
    if (doc.status === QUEUE_FOR_ROLE[user.role]) return true;
    const touched = await db.one(
      `SELECT 1 AS present FROM audit_entries
       WHERE document_id = ? AND actor_id = ? LIMIT 1`,
      [doc.id, user.id],
    );
    return Boolean(touched);
  }

  async requireView(db, user, doc) {
    if (await this.canView(db, user, doc)) return;
    if (user.role === CLERK) {
      throw forbidden(
        'FORBIDDEN_NOT_OWNER',
        'clerks may only access their own documents',
      );
    }
    throw forbidden(
      'FORBIDDEN_DOCUMENT_ACCESS',
      'this document is not in your queue and you have not acted on it',
    );
  }

  requireRole(user, role, message) {
    if (user.role !== role) throw forbidden('FORBIDDEN_ROLE', message);
  }

  requireNotLocked(doc) {
    if (doc.status === APPROVED) {
      throw conflict(
        'DOCUMENT_LOCKED',
        'the document is approved, final and locked; it cannot be changed',
      );
    }
  }

  async listDocuments(user) {
    let result;
    await withTransaction(this.db, async (tx) => {
      let rows;
      if (user.role === CLERK) {
        rows = await tx.all(
          `SELECT * FROM documents
           WHERE created_by = ? AND status != ?
           ORDER BY created_at DESC, id ASC`,
          [user.id, DELETED],
        );
      } else {
        rows = await tx.all(
          `SELECT * FROM documents
           WHERE status = ?
           ORDER BY created_at ASC, id ASC`,
          [QUEUE_FOR_ROLE[user.role]],
        );
      }
      result = [];
      for (const row of rows) {
        await appendEntry(tx, this.key, {
          documentId: row.id,
          actorId: user.id,
          actorRole: user.role,
          action: 'VIEW',
          statusBefore: row.status,
          statusAfter: row.status,
          details: { scope: 'list' },
        });
        result.push(await this.serializeDocument(tx, row));
      }
    });
    await this.advanceAnchor(this.db);
    return result;
  }

  async getDocument(user, documentId) {
    let result;
    await withTransaction(this.db, async (tx) => {
      const doc = await this.getDocumentRow(tx, documentId);
      await this.requireView(tx, user, doc);
      await appendEntry(tx, this.key, {
        documentId: doc.id,
        actorId: user.id,
        actorRole: user.role,
        action: 'VIEW',
        statusBefore: doc.status,
        statusAfter: doc.status,
        details: { scope: 'document' },
      });
      result = await this.serializeDocument(tx, doc);
    });
    await this.advanceAnchor(this.db);
    return result;
  }

  async createDocument(user, payload) {
    this.requireRole(user, CLERK, 'only clerks can create documents');
    const body = this.requireDict(payload);
    const title = this.text(body, 'title', {
      maxLength: MAX_TITLE_LENGTH,
      required: true,
    });
    const text = this.text(body, 'body', {
      maxLength: MAX_BODY_LENGTH,
      required: true,
    });
    const attachment =
      body.attachment != null ? this.parseAttachment(body.attachment) : null;

    const documentId = crypto.randomUUID();
    const now = utcNow();
    const storedName = attachment ? `${documentId}.pdf` : null;
    const storedPath = storedName
      ? path.join(this.config.attachmentsDir, storedName)
      : null;
    const digest = contentDigest(title, text);
    try {
      if (attachment) this.writeAttachment(storedPath, attachment.data);
      let result;
      await withTransaction(this.db, async (tx) => {
        await tx.run(
          `INSERT INTO documents
             (id, title, body, status, created_by, created_at, updated_at,
              revision, content_sha256, attachment_filename,
              attachment_stored_name, attachment_sha256, attachment_size)
           VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)`,
          [
            documentId,
            title,
            text,
            DRAFT,
            user.id,
            now,
            now,
            digest,
            attachment ? attachment.filename : null,
            storedName,
            attachment ? attachment.sha256 : null,
            attachment ? attachment.size : null,
          ],
        );
        await appendEntry(tx, this.key, {
          documentId,
          actorId: user.id,
          actorRole: user.role,
          action: 'CREATE',
          statusBefore: null,
          statusAfter: DRAFT,
          details: {
            title,
            content_sha256: digest,
            attachment_sha256: attachment ? attachment.sha256 : null,
          },
        });
        await tx.run(
          'UPDATE documents SET status = ?, updated_at = ? WHERE id = ?',
          [PENDING_OFFICER, now, documentId],
        );
        await appendEntry(tx, this.key, {
          documentId,
          actorId: user.id,
          actorRole: user.role,
          action: 'SUBMIT',
          statusBefore: DRAFT,
          statusAfter: PENDING_OFFICER,
          details: { revision: 1 },
        });
        result = await this.serializeDocument(
          tx,
          await this.getDocumentRow(tx, documentId),
        );
      });
      await this.advanceAnchor(this.db);
      return result;
    } catch (error) {
      if (storedPath) {
        try {
          fs.unlinkSync(storedPath);
        } catch {
          // Nothing to clean up.
        }
      }
      throw error;
    }
  }

  async editDocument(user, documentId, payload) {
    const body = this.requireDict(payload);
    const hasAttachment = Object.prototype.hasOwnProperty.call(body, 'attachment');
    if (
      body.remove_attachment !== undefined &&
      typeof body.remove_attachment !== 'boolean'
    ) {
      throw badRequest('VALIDATION_ERROR', 'remove_attachment must be a boolean');
    }
    let removeAttachment = body.remove_attachment === true;
    if (hasAttachment && removeAttachment) {
      throw badRequest(
        'VALIDATION_ERROR',
        'send either attachment or remove_attachment, not both',
      );
    }

    let oldPath = null;
    let oldBytes = null;
    try {
      let result;
      await withTransaction(this.db, async (tx) => {
        const doc = await this.getDocumentRow(tx, documentId);
        this.requireNotLocked(doc);
        this.requireRole(user, CLERK, 'only the owning clerk can edit a document');
        if (doc.created_by !== user.id) {
          throw forbidden(
            'FORBIDDEN_NOT_OWNER',
            'clerks may only edit their own documents',
          );
        }
        if (doc.status !== RETURNED) {
          throw conflict(
            'INVALID_STATUS',
            'a document can only be edited after it has been returned',
            { status: doc.status },
          );
        }

        const title = this.text(body, 'title', {
          maxLength: MAX_TITLE_LENGTH,
          fallback: doc.title,
        });
        const text = this.text(body, 'body', {
          maxLength: MAX_BODY_LENGTH,
          fallback: doc.body,
        });
        const changed = [];
        if (title !== doc.title) changed.push('title');
        if (text !== doc.body) changed.push('body');

        let newAttachment = null;
        if (hasAttachment) {
          if (body.attachment === null) {
            removeAttachment = true;
          } else {
            newAttachment = this.parseAttachment(body.attachment);
          }
        }
        if (newAttachment || removeAttachment) changed.push('attachment');

        oldPath = doc.attachment_stored_name
          ? path.join(this.config.attachmentsDir, doc.attachment_stored_name)
          : null;
        oldBytes = oldPath && fs.existsSync(oldPath) ? fs.readFileSync(oldPath) : null;
        let storedName = doc.attachment_stored_name;
        let filename = doc.attachment_filename;
        let attachmentSha = doc.attachment_sha256;
        let attachmentSize = doc.attachment_size;

        if (newAttachment) {
          storedName = `${documentId}.pdf`;
          oldPath = path.join(this.config.attachmentsDir, storedName);
          this.writeAttachment(oldPath, newAttachment.data);
          filename = newAttachment.filename;
          attachmentSha = newAttachment.sha256;
          attachmentSize = newAttachment.size;
        } else if (removeAttachment) {
          if (oldPath) {
            try {
              fs.unlinkSync(oldPath);
            } catch (error) {
              if (error.code !== 'ENOENT') throw error;
            }
          }
          storedName = filename = attachmentSha = attachmentSize = null;
        }

        const now = utcNow();
        const digest = contentDigest(title, text);
        await tx.run(
          `UPDATE documents SET
             title = ?, body = ?, updated_at = ?, content_sha256 = ?,
             attachment_filename = ?, attachment_stored_name = ?,
             attachment_sha256 = ?, attachment_size = ?
           WHERE id = ?`,
          [
            title,
            text,
            now,
            digest,
            filename,
            storedName,
            attachmentSha,
            attachmentSize,
            documentId,
          ],
        );
        await appendEntry(tx, this.key, {
          documentId,
          actorId: user.id,
          actorRole: user.role,
          action: 'EDIT',
          statusBefore: RETURNED,
          statusAfter: RETURNED,
          details: {
            changed_fields: changed,
            content_sha256: digest,
            attachment_sha256: attachmentSha,
          },
        });
        result = await this.serializeDocument(
          tx,
          await this.getDocumentRow(tx, documentId),
        );
      });
      await this.advanceAnchor(this.db);
      return result;
    } catch (error) {
      if (oldPath) {
        if (oldBytes !== null) {
          this.writeAttachment(oldPath, oldBytes);
        } else {
          try {
            fs.unlinkSync(oldPath);
          } catch {
            // Already absent.
          }
        }
      }
      throw error;
    }
  }

  async submitDocument(user, documentId) {
    let result;
    await withTransaction(this.db, async (tx) => {
      const doc = await this.getDocumentRow(tx, documentId);
      this.requireNotLocked(doc);
      this.requireRole(user, CLERK, 'only the owning clerk can submit a document');
      if (doc.created_by !== user.id) {
        throw forbidden(
          'FORBIDDEN_NOT_OWNER',
          'clerks may only submit their own documents',
        );
      }
      if (doc.status !== RETURNED) {
        throw conflict(
          'INVALID_STATUS',
          'only a returned document can be resubmitted',
          { status: doc.status },
        );
      }
      const now = utcNow();
      const revision = doc.revision + 1;
      await tx.run(
        `UPDATE documents SET
           status = ?, revision = ?, updated_at = ?,
           last_rejection_reason = NULL, last_rejected_by = NULL,
           last_rejected_at = NULL
         WHERE id = ?`,
        [PENDING_OFFICER, revision, now, documentId],
      );
      await appendEntry(tx, this.key, {
        documentId,
        actorId: user.id,
        actorRole: user.role,
        action: 'SUBMIT',
        statusBefore: RETURNED,
        statusAfter: PENDING_OFFICER,
        details: { revision },
      });
      result = await this.serializeDocument(
        tx,
        await this.getDocumentRow(tx, documentId),
      );
    });
    await this.advanceAnchor(this.db);
    return result;
  }

  async approveDocument(user, documentId) {
    let result;
    await withTransaction(this.db, async (tx) => {
      const doc = await this.getDocumentRow(tx, documentId);
      this.requireNotLocked(doc);
      if (user.role !== OFFICER && user.role !== SENIOR_OFFICER) {
        throw forbidden('FORBIDDEN_ROLE', 'only officers can approve documents');
      }
      const expected = QUEUE_FOR_ROLE[user.role];
      if (doc.status !== expected) {
        throw conflict(
          'NOT_AT_YOUR_LEVEL',
          `this document is not waiting for a ${user.role.toLowerCase()}`,
          { status: doc.status, expected_status: expected },
        );
      }

      const now = utcNow();
      let newStatus;
      let details;
      if (user.role === OFFICER) {
        newStatus = PENDING_SENIOR_OFFICER;
        details = { level: OFFICER };
        await tx.run(
          'UPDATE documents SET status = ?, updated_at = ? WHERE id = ?',
          [newStatus, now, documentId],
        );
      } else {
        newStatus = APPROVED;
        const digest = contentDigest(doc.title, doc.body);
        if (digest !== doc.content_sha256) {
          throw conflict(
            'CONTENT_INTEGRITY_ERROR',
            'the stored document does not match its content hash',
          );
        }
        let approvedAttachment = null;
        if (doc.attachment_stored_name) {
          const attachmentPath = path.join(
            this.config.attachmentsDir,
            doc.attachment_stored_name,
          );
          if (!fs.existsSync(attachmentPath)) {
            throw conflict(
              'ATTACHMENT_MISSING',
              'the attachment file is missing; approval is refused',
            );
          }
          approvedAttachment = sha256File(attachmentPath);
          if (approvedAttachment !== doc.attachment_sha256) {
            throw conflict(
              'ATTACHMENT_INTEGRITY_ERROR',
              'the attachment does not match its stored hash; approval is refused',
            );
          }
        }
        await tx.run(
          `UPDATE documents SET
             status = ?, updated_at = ?, approved_at = ?, approved_by = ?,
             approved_content_sha256 = ?, approved_attachment_sha256 = ?
           WHERE id = ?`,
          [newStatus, now, now, user.id, digest, approvedAttachment, documentId],
        );
        details = {
          level: SENIOR_OFFICER,
          content_sha256: digest,
          attachment_sha256: approvedAttachment,
        };
      }
      await appendEntry(tx, this.key, {
        documentId,
        actorId: user.id,
        actorRole: user.role,
        action: 'APPROVE',
        statusBefore: doc.status,
        statusAfter: newStatus,
        details,
      });
      result = await this.serializeDocument(
        tx,
        await this.getDocumentRow(tx, documentId),
      );
    });
    await this.advanceAnchor(this.db);
    return result;
  }

  async rejectDocument(user, documentId, payload) {
    const body = this.requireDict(payload);
    const reason = this.text(body, 'reason', {
      maxLength: MAX_REASON_LENGTH,
      required: true,
    });
    let result;
    await withTransaction(this.db, async (tx) => {
      const doc = await this.getDocumentRow(tx, documentId);
      this.requireNotLocked(doc);
      if (user.role !== OFFICER && user.role !== SENIOR_OFFICER) {
        throw forbidden('FORBIDDEN_ROLE', 'only officers can reject documents');
      }
      const expected = QUEUE_FOR_ROLE[user.role];
      if (doc.status !== expected) {
        throw conflict(
          'NOT_AT_YOUR_LEVEL',
          `this document is not waiting for a ${user.role.toLowerCase()}`,
          { status: doc.status, expected_status: expected },
        );
      }
      const now = utcNow();
      await tx.run(
        `UPDATE documents SET
           status = ?, updated_at = ?, last_rejection_reason = ?,
           last_rejected_by = ?, last_rejected_at = ?
         WHERE id = ?`,
        [RETURNED, now, reason, user.id, now, documentId],
      );
      await appendEntry(tx, this.key, {
        documentId,
        actorId: user.id,
        actorRole: user.role,
        action: 'REJECT',
        statusBefore: doc.status,
        statusAfter: RETURNED,
        details: { level: user.role, reason, revision: doc.revision },
      });
      result = await this.serializeDocument(
        tx,
        await this.getDocumentRow(tx, documentId),
      );
    });
    await this.advanceAnchor(this.db);
    return result;
  }

  async deleteDocument(user, documentId) {
    let attachmentPath = null;
    let result;
    await withTransaction(this.db, async (tx) => {
      const doc = await this.getDocumentRow(tx, documentId);
      this.requireNotLocked(doc);
      this.requireRole(user, CLERK, 'only the owning clerk can delete a document');
      if (doc.created_by !== user.id) {
        throw forbidden(
          'FORBIDDEN_NOT_OWNER',
          'clerks may only delete their own documents',
        );
      }
      if (doc.status !== RETURNED) {
        throw conflict(
          'INVALID_STATUS',
          'a document can only be deleted while it is returned',
          { status: doc.status },
        );
      }
      const now = utcNow();
      attachmentPath = doc.attachment_stored_name
        ? path.join(this.config.attachmentsDir, doc.attachment_stored_name)
        : null;
      await tx.run(
        `UPDATE documents SET status = ?, updated_at = ?, deleted_at = ?,
           deleted_by = ? WHERE id = ?`,
        [DELETED, now, now, user.id, documentId],
      );
      await appendEntry(tx, this.key, {
        documentId,
        actorId: user.id,
        actorRole: user.role,
        action: 'DELETE',
        statusBefore: RETURNED,
        statusAfter: DELETED,
        details: { title: doc.title, attachment_filename: doc.attachment_filename },
      });
      result = await this.serializeDocument(
        tx,
        await this.getDocumentRow(tx, documentId),
      );
    });
    await this.advanceAnchor(this.db);
    if (attachmentPath) {
      try {
        fs.unlinkSync(attachmentPath);
      } catch (error) {
        if (error.code !== 'ENOENT') {
          console.error(`could not remove attachment after delete: ${error.message}`);
        }
      }
    }
    return result;
  }

  async getAttachment(user, documentId) {
    let payload;
    await withTransaction(this.db, async (tx) => {
      const doc = await this.getDocumentRow(tx, documentId);
      await this.requireView(tx, user, doc);
      if (!doc.attachment_stored_name) {
        throw notFound('ATTACHMENT_NOT_FOUND', 'this document has no attachment');
      }
      const attachmentPath = path.join(
        this.config.attachmentsDir,
        doc.attachment_stored_name,
      );
      if (!fs.existsSync(attachmentPath)) {
        throw notFound(
          'ATTACHMENT_NOT_FOUND',
          'the attachment file is missing on disk',
        );
      }
      const data = fs.readFileSync(attachmentPath);
      const actualHash = sha256Bytes(data);
      await appendEntry(tx, this.key, {
        documentId,
        actorId: user.id,
        actorRole: user.role,
        action: 'DOWNLOAD',
        statusBefore: doc.status,
        statusAfter: doc.status,
        details: { filename: doc.attachment_filename, sha256: actualHash },
      });
      payload = {
        filename: doc.attachment_filename,
        data,
        sha256: actualHash,
        matches_tracked: actualHash === doc.attachment_sha256,
      };
    });
    await this.advanceAnchor(this.db);
    return payload;
  }

  async getAudit(user, documentId) {
    let entries;
    await withTransaction(this.db, async (tx) => {
      const doc = await this.getDocumentRow(tx, documentId);
      await this.requireView(tx, user, doc);
      const rows = await tx.all(
        'SELECT * FROM audit_entries WHERE document_id = ? ORDER BY seq ASC',
        [documentId],
      );
      entries = rows.map(serializeEntry);
      await appendEntry(tx, this.key, {
        documentId,
        actorId: user.id,
        actorRole: user.role,
        action: 'VIEW',
        statusBefore: doc.status,
        statusAfter: doc.status,
        details: { scope: 'audit_history' },
      });
    });
    await this.advanceAnchor(this.db);
    return { document_id: documentId, entries };
  }

  async checkIntegrity(user, documentId) {
    let result;
    await withTransaction(this.db, async (tx) => {
      const doc = await this.getDocumentRow(tx, documentId);
      await this.requireView(tx, user, doc);
      if (doc.status !== APPROVED) {
        throw conflict(
          'NOT_APPROVED',
          'only approved documents have a locked content hash',
          { status: doc.status },
        );
      }
      const currentContent = contentDigest(doc.title, doc.body);
      const contentMatches = currentContent === doc.approved_content_sha256;

      const expectedAttachment = doc.approved_attachment_sha256;
      let currentAttachment = null;
      let attachmentFilePresent = null;
      let attachmentMatches;
      if (expectedAttachment !== null) {
        const attachmentPath = doc.attachment_stored_name
          ? path.join(this.config.attachmentsDir, doc.attachment_stored_name)
          : null;
        if (attachmentPath && fs.existsSync(attachmentPath)) {
          attachmentFilePresent = true;
          currentAttachment = sha256File(attachmentPath);
          attachmentMatches = currentAttachment === expectedAttachment;
        } else {
          attachmentFilePresent = false;
          attachmentMatches = false;
        }
      } else {
        attachmentMatches = doc.attachment_stored_name === null;
      }

      const approval = await tx.one(
        `SELECT details FROM audit_entries
         WHERE document_id = ? AND action = 'APPROVE' AND status_after = 'APPROVED'
         ORDER BY seq DESC LIMIT 1`,
        [documentId],
      );
      let auditContent = null;
      let auditAttachment = null;
      if (approval) {
        try {
          const approvalDetails = JSON.parse(approval.details);
          auditContent = approvalDetails.content_sha256 ?? null;
          auditAttachment = approvalDetails.attachment_sha256 ?? null;
        } catch {
          // Leave the snapshot unreadable; the comparison fails.
        }
      }
      const snapshotMatchesAudit =
        auditContent === doc.approved_content_sha256 &&
        auditAttachment === doc.approved_attachment_sha256;

      const valid = contentMatches && attachmentMatches && snapshotMatchesAudit;
      result = {
        document_id: documentId,
        status: doc.status,
        approved_at: doc.approved_at,
        approved_by: await this.userBrief(tx, doc.approved_by),
        stored: {
          content_sha256: doc.approved_content_sha256,
          attachment_sha256: expectedAttachment,
        },
        audit_snapshot: {
          content_sha256: auditContent,
          attachment_sha256: auditAttachment,
        },
        current: {
          content_sha256: currentContent,
          attachment_sha256: currentAttachment,
        },
        content_matches: contentMatches,
        attachment_matches: attachmentMatches,
        snapshot_matches_audit: snapshotMatchesAudit,
        attachment_file_present: attachmentFilePresent,
        valid,
        checked_at: utcNow(),
      };
      await appendEntry(tx, this.key, {
        documentId,
        actorId: user.id,
        actorRole: user.role,
        action: 'VIEW',
        statusBefore: doc.status,
        statusAfter: doc.status,
        details: {
          scope: 'integrity',
          valid,
          content_matches: contentMatches,
          attachment_matches: attachmentMatches,
          snapshot_matches_audit: snapshotMatchesAudit,
        },
      });
    });
    await this.advanceAnchor(this.db);
    return result;
  }

  async verifyAudit() {
    let anchor;
    try {
      anchor = readAnchor(this.config.auditHeadPath);
    } catch (error) {
      return {
        valid: false,
        code: 'CHECKPOINT_INVALID',
        message: error.message,
      };
    }
    return verifyChain(this.db, this.key, anchor);
  }

  writeAttachment(filePath, data) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    const temp = path.join(
      path.dirname(filePath),
      `.${path.basename(filePath)}.${crypto.randomUUID()}.tmp`,
    );
    try {
      const fd = fs.openSync(temp, 'wx', 0o600);
      try {
        fs.writeSync(fd, data);
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      fs.renameSync(temp, filePath);
    } finally {
      try {
        fs.unlinkSync(temp);
      } catch {
        // Renamed or never created.
      }
    }
  }
}

module.exports = { WorkflowService, loadOrCreateAuditKey };
