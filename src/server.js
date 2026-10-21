'use strict';

const http = require('node:http');

const { ApiError } = require('./errors');
const { WorkflowService } = require('./service');

const MAX_REQUEST_BYTES = 20 * 1024 * 1024;
const DOCUMENT_PATH = /^\/documents\/([^/]+)$/;
const DOCUMENT_ACTION_PATH =
  /^\/documents\/([^/]+)\/(submit|approve|reject|attachment|audit|integrity)$/;

function requireMethod(actual, expected) {
  if (actual !== expected) {
    throw new ApiError(405, 'METHOD_NOT_ALLOWED', `this endpoint requires ${expected}`);
  }
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    const declared = Number.parseInt(req.headers['content-length'] || '0', 10);
    if (Number.isFinite(declared) && declared > MAX_REQUEST_BYTES) {
      reject(
        new ApiError(
          413,
          'PAYLOAD_TOO_LARGE',
          `request body must be at most ${MAX_REQUEST_BYTES} bytes`,
        ),
      );
      req.resume();
      return;
    }
    const chunks = [];
    let size = 0;
    let failed = false;
    req.on('data', (chunk) => {
      if (failed) return;
      size += chunk.length;
      if (size > MAX_REQUEST_BYTES) {
        failed = true;
        reject(
          new ApiError(
            413,
            'PAYLOAD_TOO_LARGE',
            `request body must be at most ${MAX_REQUEST_BYTES} bytes`,
          ),
        );
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (failed) return;
      const raw = Buffer.concat(chunks);
      if (raw.length === 0) {
        resolve({});
        return;
      }
      try {
        const value = JSON.parse(raw.toString('utf8'));
        if (!value || typeof value !== 'object' || Array.isArray(value)) {
          reject(
            new ApiError(
              400,
              'VALIDATION_ERROR',
              'request body must be a JSON object',
            ),
          );
          return;
        }
        resolve(value);
      } catch {
        reject(new ApiError(400, 'INVALID_JSON', 'request body must be valid JSON'));
      }
    });
    req.on('error', (error) => {
      if (!failed) reject(error);
    });
  });
}

function sendJson(res, status, payload) {
  const body = Buffer.from(JSON.stringify(payload), 'utf8');
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': body.length,
    'Cache-Control': 'no-store',
    Connection: 'close',
  };
  if (status === 401) headers['WWW-Authenticate'] = 'Bearer';
  res.writeHead(status, headers);
  res.end(body);
}

function sendAttachment(res, attachment) {
  res.writeHead(200, {
    'Content-Type': 'application/pdf',
    'Content-Disposition': `attachment; filename="${attachment.filename}"`,
    'Content-Length': attachment.data.length,
    'Cache-Control': 'no-store',
    'X-Content-SHA256': attachment.sha256,
    'X-Content-Matches-Tracked-Hash': attachment.matches_tracked ? 'true' : 'false',
    Connection: 'close',
  });
  res.end(attachment.data);
}

async function authenticate(service, req) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) {
    throw new ApiError(401, 'UNAUTHENTICATED', 'a valid bearer token is required');
  }
  const token = header.slice('Bearer '.length).trim();
  if (!token) {
    throw new ApiError(401, 'UNAUTHENTICATED', 'a valid bearer token is required');
  }
  return { user: await service.authenticate(token), token };
}

async function handle(service, req, res) {
  let pathname;
  try {
    pathname = new URL(req.url, 'http://localhost').pathname;
  } catch {
    return sendJson(res, 404, {
      error: { code: 'NOT_FOUND', message: 'no such endpoint' },
    });
  }
  if (pathname.length > 1) pathname = pathname.replace(/\/+$/, '') || '/';
  const method = req.method;

  try {
    if (pathname === '/auth/login') {
      requireMethod(method, 'POST');
      const body = await readJson(req);
      return sendJson(res, 200, await service.login(body.username, body.password));
    }

    const { user, token } = await authenticate(service, req);

    if (pathname === '/me') {
      requireMethod(method, 'GET');
      return sendJson(res, 200, service.getMe(user));
    }

    if (pathname === '/auth/logout') {
      requireMethod(method, 'POST');
      await service.logout(token);
      return sendJson(res, 200, { ok: true });
    }

    if (pathname === '/documents') {
      if (method === 'GET') {
        return sendJson(res, 200, {
          documents: await service.listDocuments(user),
        });
      }
      if (method === 'POST') {
        const body = await readJson(req);
        return sendJson(res, 201, await service.createDocument(user, body));
      }
      throw new ApiError(
        405,
        'METHOD_NOT_ALLOWED',
        'method not allowed for this endpoint',
      );
    }

    if (pathname === '/audit/verify') {
      requireMethod(method, 'GET');
      return sendJson(res, 200, await service.verifyAudit());
    }

    let match = DOCUMENT_PATH.exec(pathname);
    if (match) {
      const documentId = match[1];
      if (method === 'GET') {
        return sendJson(res, 200, await service.getDocument(user, documentId));
      }
      if (method === 'PATCH') {
        const body = await readJson(req);
        return sendJson(
          res,
          200,
          await service.editDocument(user, documentId, body),
        );
      }
      if (method === 'DELETE') {
        return sendJson(res, 200, await service.deleteDocument(user, documentId));
      }
      throw new ApiError(
        405,
        'METHOD_NOT_ALLOWED',
        'method not allowed for this endpoint',
      );
    }

    match = DOCUMENT_ACTION_PATH.exec(pathname);
    if (match) {
      const documentId = match[1];
      const action = match[2];
      if (action === 'submit') {
        requireMethod(method, 'POST');
        return sendJson(
          res,
          200,
          await service.submitDocument(user, documentId),
        );
      }
      if (action === 'approve') {
        requireMethod(method, 'POST');
        return sendJson(
          res,
          200,
          await service.approveDocument(user, documentId),
        );
      }
      if (action === 'reject') {
        requireMethod(method, 'POST');
        const body = await readJson(req);
        return sendJson(
          res,
          200,
          await service.rejectDocument(user, documentId, body),
        );
      }
      if (action === 'attachment') {
        requireMethod(method, 'GET');
        return sendAttachment(res, await service.getAttachment(user, documentId));
      }
      if (action === 'audit') {
        requireMethod(method, 'GET');
        return sendJson(res, 200, await service.getAudit(user, documentId));
      }
      if (action === 'integrity') {
        requireMethod(method, 'GET');
        return sendJson(res, 200, await service.checkIntegrity(user, documentId));
      }
    }

    throw new ApiError(404, 'NOT_FOUND', 'no such endpoint');
  } catch (error) {
    if (error instanceof ApiError) {
      return sendJson(res, error.status, error.toBody());
    }
    console.error('unhandled error:', error && error.stack ? error.stack : error);
    return sendJson(res, 500, {
      error: { code: 'INTERNAL_ERROR', message: 'unexpected server error' },
    });
  }
}

async function createServer(config, service) {
  const workflow = service || new WorkflowService(config);
  await workflow.initialize();
  const server = http.createServer((req, res) => {
    handle(workflow, req, res).catch((error) => {
      console.error('request failed:', error);
      if (!res.headersSent) {
        sendJson(res, 500, {
          error: { code: 'INTERNAL_ERROR', message: 'unexpected server error' },
        });
      } else {
        res.end();
      }
    });
  });
  server.service = workflow;
  return server;
}

module.exports = { createServer };
