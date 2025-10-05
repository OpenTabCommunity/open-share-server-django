
# Open Share Server Django

> Short: server implementation of the Open Share protocol — registration, CRL, trust root and light management plane. Implements OpenAPI + JSON schemas in `openapi/` and conformance tests in `tests/conformance/`.

---

## Table of contents

* Overview & goals
* What to implement (product backlog)
* Repo layout & conventions
* Quick start — dev (Docker)
* Deployment — prod notes
* API & schema contract rules
* Secret & key management (Ed25519 server signing key)
* Database & migrations
* Testing & conformance
* Coding standards & static analysis
* Logging, monitoring, error reporting
* Troubleshooting & FAQ
* Appendix: Modular Django settings (drop-in)

---

## Overview & goals

This repo implements the canonical **Registration Server** from the Open Share protocol:

* `POST /device/register` — accepts device pubkey + metadata, issues a signed **device certificate** (signed with the server Ed25519 signing key).
* `GET /crl` — returns the latest signed CRL (ETag/If-None-Match supported).
* `GET /trustroot` — returns server trust roots and supported protocol versions.
* `POST /device/revoke` — revoke device and increment CRL version.
* `GET /account/devices` — list devices for an account.
* `POST /account/register` — optional account creation (bootstrap).
* Add admin UI / management commands for key rotation, CRL issuance and audit.

Goals:

* Contract-first: API defined by `openapi/openapi.yaml` & JSON schemas in `openapi/components/schemas`.
* Strong crypto: Ed25519 signing, short-lived certs, CRL with versioning.
* Testable: conformance test harness under `tests/conformance/`.

---

## What to implement (developer backlog / minimal viable server)

Make these endpoints match the OpenAPI in the other repo exactly (contracts + examples):

1. `POST /account/register` — create account; returns `account_id` + `api_token`
2. `POST /device/register` — authenticated by `Bearer api_token`; accepts `{ device_id, pubkey_ed25519, metadata }` -> returns device certificate JSON matching `device-cert.schema.json`. Must:

   * Validate JSON schema
   * Verify `device_id` uniqueness (per account)
   * Store `pubkey` (raw bytes) in DB
   * Issue certificate with server signature (Ed25519)
   * Store certificate in `device_certs` + set device status `active`
   * Record audit log entry
3. `GET /account/devices` — returns device certs (public fields only)
4. `POST /device/revoke` — mark device revoked, append CRL entry, produce new signed CRL (`crls`), publish via `GET /crl`
5. `GET /crl` — returns latest `crl_blob` and `ETag` (use CRL `version` as ETag)
6. `GET /trustroot` — returns server public key(s) and `min_protocol_version` / `max_protocol_version`

Extra / nice-to-have:

* `POST /device/renew` — rotate cert for a device
* Admin endpoints to rotate trustroot (with overlapping roots accepted)
* Web UI for admin operations
* Rate-limits + throttling on registration to prevent abuse

---

## Repo layout & conventions 

```
.
├── docker/...
├── docker-compose.yml
├── Dockerfile
├── .env.example
├── manage.py
├── openshare/                # Django project
│   ├── settings/
│   │   ├── base.py
│   │   ├── development.py
│   │   └── production.py
│   ├── urls.py
│   └── wsgi.py
├── apps/
│   ├── accounts/
│   ├── devices/
│   ├── api/                   # DRF views/routers/spectacular
│   └── conformance/           # conformance helpers
├── openapi/                   # canonical OpenAPI.yaml + JSON schemas (copy from protocol repo)
├── tests/
│   ├── unit/
│   └── integration/
└── README.md
```

**Apps**:

* `accounts` — models for account, auth tokens, registration
* `devices` — device model, cert issuance, device_certs, crl logic
* `api` — DRF viewsets/serializers wired to OpenAPI
* `conformance` — test helpers to run the other repo's conformance vectors

---

## Quick start — development

1. Copy `.env.example` -> `.env` and fill values (DB, REDIS, signing keys if you have them).
2. Start with Docker compose (the compose file from your other repo):

```bash
docker compose up --build
```

3. Run local conformance tests:

```bash
# inside docker or locally with the venv that has jsonschema/pynacl
python3 -m pip install -r tests/conformance/requirements.txt
chmod +x tests/conformance/runner/run_local_tests.sh
tests/conformance/runner/run_local_tests.sh
```

4. Access admin UI at `http://localhost:8000/admin` (create superuser with `manage.py createsuperuser`).

---

## Architecture notes / data flow

* All authoritative PKI data (trust root, CRL) are persisted in DB `crls` table.
* Device certs are canonical JSON signed with server Ed25519 key. Server stores only signature binary and canonical cert JSON (not device private keys).
* Manifest + chunk logic: server stores manifests in `file_manifests` and references chunks by id, but does not serve file contents — file transfers are P2P LAN-first as per spec.
* Use `current_crl` table or a cache to compute ETag quickly.

---

## API & schema contract rules (mandatory)

1. Always validate incoming JSON against the JSON Schema in `openapi/components/schemas/*` — use `jsonschema` or library that supports draft-2020-12.
2. When producing certs or CRL, sign canonicalized JSON using the deterministic encoding used in conformance tests (sorted keys, compact separators) — **document canonicalization clearly**.
3. Responses must match the OpenAPI examples: field names, formats (RFC3339 datetimes), and base64url for keys/signatures.
4. Use `ETag` headers for `GET /crl` (value = CRL version or hash).
5. Use HTTPS in production and `securitySchemes` as defined in OpenAPI (bearer tokens). Mutual TLS may be an opt-in for admin endpoints.

---

## Secret & Key management (very important)

**Server signing key (Ed25519)**:

* **Do not store in DB in plaintext**. Prefer HSM / Vault. If you must store it on disk (for dev), protect with filesystem perms and keep out of VCS.
* Recommended pattern:

  * Use Vault or KMS to fetch private key at boot time.
  * Expose only the public key via `GET /trustroot`.
  * Support key rotation: keep old keys for verification until all devices migrate. Implement `trust_roots` as a list with `valid_from`/`valid_to`.
* For development only, generate key by `pynacl` and keep in `.env` or `secrets/` with strict perms.

**Suggested env vars**:

* `SIGNING_KEY_TYPE=ed25519`
* `SIGNING_KEY_PATH=/run/secrets/signing_key` or `SIGNING_KEY_BASE64=...`
* `VAULT_ADDR`, `VAULT_ROLE_ID`, etc. if using Vault

**Signing helpers**:

* Put signing code in `apps.devices.crypto` — thin wrapper around `pynacl` (or libsodium via C lib).
* Always sign canonicalized bytes; keep signing logic isolated and heavily unit-tested.

---

## Database & migrations

* Use the provided PostgreSQL schema as the canonical mapping.
* Django models should match schema columns and types; use `BinaryField` for raw public keys/signatures or `models.BinaryField` with `editable=False`.
* Use manual migrations for any DB features not directly supported by Django ORM (e.g., `CREATE TYPE device_status` or `pgcrypto` extension). Add SQL migrations using `RunSQL`.
* Keep `device_certs` and `crls` as audit-capable objects in DB; never silently overwrite.
* Use `django-db-connection-pool` / pgBouncer in production.

---

## Conformance & tests

* Use `pytest-django` + `factory_boy` for tests.
* Keep conformance tests in `tests/conformance/` calling into the other repo's test vectors. Provide an integration test that fetches generated vectors and validates server behavior.
* Unit tests:

  * crypto signing & verification
  * schema validation of requests and responses
  * DB transactions for cert issuance + audit logging + CRL updates
* Integration tests:

  * full register flow
  * revocation and CRL propagation
* Use coverage and require a minimal coverage threshold (e.g., 85%) in CI.

---

## Coding standards & static analysis

Adopt strict automated linting/formatting:

* **Formatting**: `black` (configurable line length 88)
* **Linting**: `ruff` (fast), `flake8` (optional)
* **Imports**: `isort`
* **Type checking**: `mypy` (strict mode for all new code, gradual adoption allowed)
* **Pre-commit hooks**: `.pre-commit-config.yaml` exists — ensure hooks for `black`, `ruff`, `isort`, `check-yaml`, `end-of-file-fixer`.
* **Commit messages**: Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`); enable a commit-msg hook if desired.
* **Docstrings**: Google or numpy style, use `pydocstyle` optionally.

## REST framework & API docs

* Use **Django REST Framework** (DRF) for API views.
* Use **drf-spectacular** to auto-generate OpenAPI v3.1 from DRF. Configure it to use the canonical `openapi/openapi.yaml` as the source-of-truth (or add a CI check ensuring generated spec is compatible).
* Always add `examples` in serializers that reference `openapi/components/examples`.
* Add request/response schema validation middleware that ensures responses match `file-manifest.schema.json` etc. (optional but highly recommended).

DRF settings hint:

```py
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.TokenAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.LimitOffsetPagination",
    "PAGE_SIZE": 50,
}
SPECTACULAR_SETTINGS = {
    "TITLE": "Open Share Registration API",
    "VERSION": "1.0.0",
    "SCHEMA_PATH_PREFIX": r"/api/",
}
```

---

## Rate limiting, Abuse protection

* Protect `POST /device/register` and `POST /account/register` with rate limits. Use DRF throttling or a gateway (Cloudflare, Kong).
* Optionally add CAPTCHA for human-facing account creation.

---

## Logging & monitoring

* Structured JSON logs (use `python-json-logger` or custom formatter and also use structlog).
* Include correlation ids: instrument incoming requests, pass correlation id to logs and background tasks.
* Expose `/healthz` and `/readyz` endpoints:

  * `/healthz` = basic app up
  * `/readyz` = DB connectivity and migrations health

Logging example:

```py
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "fmt": "%(asctime)s %(levelname)s %(name)s %(message)s",
        }
    },
    "handlers": {
        "stdout": {"class": "logging.StreamHandler", "formatter": "json"},
    },
    "root": {"handlers": ["stdout"], "level": "INFO"},
}
```

---

## Security checklist (must-follow)

* Enforce HTTPS in production. `SECURE_SSL_REDIRECT = True`
* Set `SESSION_COOKIE_SECURE = True`, `CSRF_COOKIE_SECURE = True`
* `SECURE_HSTS_SECONDS >= 31536000`, `SECURE_HSTS_INCLUDE_SUBDOMAINS = True` (after testing)
* Use `Argon2` for password hashing: `PASSWORD_HASHERS` with `django.contrib.auth.hashers.Argon2PasswordHasher`.
* Keep `DEBUG = False` in prod.
* Set `ALLOWED_HOSTS` to concrete hosts.
* Use `django-csp` for content security policy.
* Avoid storing private signing keys in git. Use Vault/KMS.

---

## Celery & background tasks

* Use Celery for any asynchronous tasks (CRL publishing, garbage collecting chunks, sending notifications).
* Configure broker & result backend via env (`CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND`).
* Provide a `celery.py` in Django project that imports tasks and uses `app.autodiscover_tasks()`.

---

## Troubleshooting & FAQ

* `Migration errors`: ensure DB extensions (`pgcrypto`, `citext`) created via SQL migration.
* `Crypto verification`: ensure canonicalization used by server matches conformance runner exactly (sorted keys, no extra spaces).
* `Slow CRL queries`: add index on `crl_entries.revoked_device_id` and cache `current_crl.crl_id`.
* `Missing keys in production`: ensure secrets are provisioned via your secrets manager and the container fetches them at start.

---

## Final notes & checklist for maintainers

* Keep `openapi/` in sync with DRF-generated OpenAPI; add a CI job that diffs the generated spec to the canonical `openapi/openapi.yaml`. If they differ, fail CI and require reconciliation.
* Make signing/verification crypto small, well-tested modules (`apps.devices.crypto`) and never reimplement primitives — use `pynacl`.
* Write integration tests for the entire register -> CRL lifecycle.
* Document canonical JSON canonicalization and keep test vectors in `tests/conformance/vectors`.
* Establish rotation plan & migration steps for trust-root changes.

---
