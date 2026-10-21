# Document approval API

Node.js + PostgreSQL backend for the Helpforce workflow. Clerks create documents,
an officer reviews them, and a senior officer gives final approval. Approved
documents are locked. There is no frontend.

## Running

```bash
docker compose up --build
```

This starts PostgreSQL and the API on `http://localhost:8000`. Database files
live in a named volume; PDFs, the audit key and checkpoint are in `./data`. The
first build pulls the image and `pg`; afterwards it runs offline.

With an existing local Postgres:

```bash
export DATABASE_URL=postgresql://helpforce:helpforce@127.0.0.1:5432/helpforce
npm install && npm start
```

The schema and users are created at startup. The default `DATABASE_URL` is
`localhost:5432`; the compose API overrides it to `db:5432`. `DATA_DIR`, `HOST`
and `PORT` can also be set.

Users: `clerk1` / `clerk1-demo-pass`, `clerk2` / `clerk2-demo-pass`, `officer` /
`officer-demo-pass`, `senior` / `senior-demo-pass`.

## API

`POST /auth/login` with `{"username","password"}` returns a token. Send it as
`Authorization: Bearer <token>` on every other request.

```text
POST   /auth/login, /auth/logout
GET    /me, /documents, /documents/:id,
       /documents/:id/attachment|audit|integrity, /audit/verify
POST   /documents, /documents/:id/submit|approve|reject
PATCH  /documents/:id
DELETE /documents/:id
```

Create and edit bodies use `title`, `body` and an optional attachment object
(`filename` + `content_base64`). Reject requires `reason`. Errors look like
`{"error": {"code": "DOCUMENT_LOCKED", "message": "..."}}`; 400 is validation,
401 auth, 403 role/ownership, 404 missing and 409 wrong status or locked.

## Tests

```bash
npm test
```

The 19 tests need Postgres on `localhost:5432` by default. With the compose
database, run
`DATABASE_URL=postgresql://helpforce:helpforce@127.0.0.1:55432/helpforce npm test`.
Each run creates and drops its own schema. Coverage includes roles/status,
cross-clerk access, approvals and resubmission, locking, integrity, audit,
concurrency and tampering.

## Data model

`users` (one role), `sessions` (hashed tokens), `documents` and `audit_entries`.
Statuses are `DRAFT`, `PENDING_OFFICER`, `PENDING_SENIOR_OFFICER`, `RETURNED`,
`APPROVED` and `DELETED`. Create and submit are one request. Only the owning
clerk can edit, resubmit or delete, and only while `RETURNED`; resubmitting bumps
`revision` and returns the document to the officer queue.

All checks happen in a transaction with a global advisory lock, so concurrent
approvals cannot both succeed. `audit_entries` has no foreign key to `documents`,
so history survives deletion. Final approval stores SHA-256 hashes of the content
and PDF; `GET /documents/:id/integrity` recalculates both and compares them with
the final `APPROVE` audit row.

## Audit log

Each row has `seq`, actor/role, action, document, timestamp, before/after status,
details, the previous hash and an HMAC-SHA256 hash of the row. Rows are written
in the same transaction as the action. The key is outside the database
(`data/audit.key` or `AUDIT_HMAC_KEY`), and a checkpoint stores the last verified
hash. `GET /audit/verify` and `npm run verify-audit` check the chain.

This does not protect against full filesystem access: the key can be read, or
the database and checkpoint rewritten together. If both are destroyed it looks
like a fresh install. A real deployment would use an external append-only store
for the head hash and a KMS/HSM for the key.

## Assumptions and next steps

- Attachments are base64 JSON, max 10 MB, with a PDF signature check.
- No draft API: edit, submit and delete only while `RETURNED`.
- Officers see their queue plus documents they have touched; clerks only their
  own. Listing, opening a document, reading its audit/integrity report and
  downloading the PDF all write audit entries.
- No admin role; audit endpoints are read-only.
- The key and checkpoint are local files, only as safe as the host.

Next: external anchoring, KMS-backed keys, pagination, idempotency, stricter PDF
validation and an OpenAPI spec.
