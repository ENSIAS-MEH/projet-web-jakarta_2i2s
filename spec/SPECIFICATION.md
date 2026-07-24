# SecBret — Unified System Specification

**Version:** 1.0 ·

This is the **single source of truth** for SecBret. Two things live outside it, deliberately: the REST contract is machine-defined in `spec/openapi.yaml` (Part III is its prose rendering), and the database schema is whatever the Flyway migrations actually run (Part IV describes them, but the migrations win if they ever disagree). Everything else is here.

## How this document is organized

| Part | Title | Contents |
|------|-------|----------|
| **Part I** | This preface | Document map, asset index, reference convention |
| **Part II** | Design & Architecture | Normative conventions, canonical ownership, tech stack, MVC, RBAC, security, deployment, AI engine, error handling, failure modes, NFRs |
| **Part III** | REST API | Endpoint definitions, request/response, errors, enumerations |
| **Part IV** | Database Schema | DDL, JSONB structures, indexes, Flyway migrations, triggers, query patterns |
| **Part V** | Frontend UX, Accessibility & Cross-Platform | Error-to-UI mapping, loading/feedback states, WCAG 2.2 AA accessibility, responsive & browser compatibility |

## Companion assets (not inlined)

These remain as standalone files in `spec/` because they are machine-readable contracts or binary diagram artifacts, not prose:

| Asset | File | Purpose |
|-------|------|---------|
| OpenAPI contract | `spec/openapi.yaml` | Machine-readable REST contract (source of truth for Part III) |
| Architecture diagrams (source) | `spec/architecture.puml` | C4 context/container, MVC layers, deployment, use cases |
| Data model (source) | `spec/data-model.puml` | ERD and physical schema |
| Workflow sequences (source) | `spec/workflows.puml` | Scan, incident, report, auth, share-link sequences |
| Rendered diagrams | `spec/SecBret_*.png` | PNG exports of the above |

## Reference convention

Cross-references use the form `Part II §E`, `Part III §9`, …. `openapi.yaml`, the `*.puml` sources, and the `*.png` diagrams are referenced by filename.

---

# Part II — Design & Architecture

## Document Index

| Document | Path | Description |
|----------|------|-------------|
| Architecture Diagrams | `spec/architecture.puml` | C4 context, container, MVC layers, deployment, use cases |
| Data Model | `spec/data-model.puml` | ERD and physical DB schema diagrams |
| Workflow Sequences | `spec/workflows.puml` | Scan, incident, report, auth, share link sequences |
| REST API Specification | `Part III` | Full endpoint definitions, request/response, errors, enums |
| Database Schema | `Part IV` | SQL DDL, JSONB structures, indexes, Flyway naming, query patterns |
| Frontend UX / A11y / Cross-Platform | `Part V` | Error-to-UI mapping, loading/feedback states, WCAG 2.2 AA accessibility, responsive & browser compatibility |
| Architecture Decision Records | *(decisions summarized in this row)* | ADR-0001 … ADR-0007 decisions: hybrid AI engine, PDFs-in-DB, single Maven module, JSP/HTMX frontend, in-process job queue, Docker-Compose deployment, Postgres 14 baseline |
| This Document | `Part II` | Design decisions, tech stack, deployment, RBAC, security |

---

## A. Normative Conventions

> "The key words 'MUST', 'MUST NOT', 'SHALL', 'SHALL NOT', 'SHOULD', 'SHOULD NOT', 'RECOMMENDED', and 'MAY' in this specification set are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119)."

---

## A.1 Canonical Ownership

Every topic has exactly one authoritative document. Other documents reference the canonical source instead of duplicating it.

| Topic | Canonical Source |
|-------|-----------------|
| REST API | `Part III` |
| OpenAPI Contract | `spec/openapi.yaml` |
| Database Schema | `Part IV` |
| Security Policies | `Part II` §5 |
| RBAC | `Part II` §4 |
| Deployment | `Part II` §6 |
| Architecture | `spec/architecture.puml` |
| Workflows | `spec/workflows.puml` |
| Password Policy | `Part II` §B |
| URL Normalization | `Part II` §C |
| Error Response Standard | `Part II` §E |
| Error-to-UI Mapping & UX States | `Part V` §1 |
| Accessibility (WCAG 2.2 AA) | `Part V` §2 |
| Cross-Platform / Responsive / Browser Support | `Part V` §3 |
| Enumerations | `Part II` §G |

---

## A.2 Authorization Philosophy

SecBret uses a three-tier authorization model for all authenticated endpoints:

| Status Code | Condition |
|-------------|-----------|
| **401 Unauthorized** | The request lacks a valid session (unauthenticated). The caller must log in first. |
| **403 Forbidden** | The caller is authenticated but their role does not permit the requested action. For example, a REPORTER calling `GET /api/v1/admin/reviews/pending`. |
| **404 Not Found** | The caller is authenticated and permitted, but the resource does not exist **or** the caller is not authorized to know it exists. This is used to prevent data enumeration. For example, a REPORTER querying `GET /api/v1/scan/url/{urlId}` for a URL they never scanned receives 404—not 403—to avoid leaking the existence of the URL. |

When an resource ownership check is used for privacy (e.g., a REPORTER may only view their own scan jobs), the endpoint returns **404** for both "not found" and "not yours" to prevent data enumeration. It never returns **403** for ownership failures.

Endpoint descriptions in the API specification reference this section rather than repeating the authorization rationale.

---

## B. Password Policy

> Canonical source. All other documents reference this section.

| Requirement | Detail |
|-------------|--------|
| **Minimum length** | 12 characters |
| **Composition** | None. No mandatory special characters, digits, or uppercase letters. |
| **Breach check** | MUST NOT appear in known breach datasets (HIBP k-anonymity check) |
| **Recommended length** | 16+ characters or a passphrase |
| **Hashing** | BCrypt with cost factor 12 |
| **Storage** | Hashed only; plaintext never stored |

---

## C. URL Normalization Algorithm

> Canonical source. All other documents reference this section.

Before insertion or lookup, every submitted URL is normalized as follows:

1. Lowercase scheme and host
2. Remove default ports
3. Remove URL fragment (`#`)
4. Collapse duplicate path separators
5. Remove trailing slash except root
6. Sort query parameters lexicographically
7. Convert hostname to punycode
8. Compute SHA-256 hash of the normalized form

**Storage:**

| Column | Purpose |
|--------|---------|
| `original_url` | Raw URL as submitted by the user |
| `normalized_hash` | SHA-256 of the normalized URL (used for deduplication) |

Deduplication MUST use `normalized_hash`. Two URLs that differ only in case, port, trailing slash, or query-parameter order are considered the same URL.

---

## D. API Compatibility & Versioning

SecBret exposes a single API version: **v1** (`/api/v1`).

| Change Type | Allowed in v1 | Requires v2 |
|-------------|---------------|-------------|
| New endpoints | ✓ Yes | — |
| New request/response fields | ✓ Yes | — |
| New enum values | ✓ Yes (non-breaking) | — |
| Remove fields | ✗ No | ✓ Yes |
| Remove enum values | ✗ No | ✓ Yes |
| Change endpoint behavior | ✗ No | ✓ Yes |

Breaking changes (removing fields, changing semantics, removing enum values) require a new major version (`v2`). Client code can rely on v1 field and enum stability.

---

## E. Error Response Standard

All API errors follow a single structure:

```json
{
  "status": 400,
  "error": "Bad Request",
  "message": "URL is not a valid HTTP/HTTPS URL",
  "timestamp": "2026-06-17T10:00:00Z",
  "path": "/api/v1/scan",
  "correlationId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

Validation errors additionally contain:

```json
{
  "status": 400,
  "error": "Bad Request",
  "message": "Validation failed",
  "timestamp": "2026-06-15T09:30:00Z",
  "path": "/api/v1/scan",
  "correlationId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "errors": [
    { "field": "url", "message": "URL is not valid" }
  ]
}
```

No inconsistent field names (e.g., `errorMessage`, `reason`, `validationError`) are used.

The OpenAPI schema `ErrorResponse` (`openapi.yaml`) and the API specification (`Part III`) match this structure exactly.

---


## F. Deletion Policy Matrix

Every entity in the system follows one of the following deletion strategies:

| Entity | Strategy | Mechanism |
|--------|----------|-----------|
| `secbret_user` | Hard delete | `DELETE FROM secbret_user`; DB cascade fires: `api_token`, `password_reset_token`, `idempotency_key`, `webhook_subscription` are CASCADE DELETED; `scan_job`, `user_report`, `report_job`, `share_link`, `security_team_review`, `audit_log` have their user FK columns set to NULL via `ON DELETE SET NULL`. The V20 trigger `tombstone_audit_before_delete` writes `actor_username = 'deleted_{uuid}'` before the cascade nullifies `actor_id`. |
| `scanned_url` | Soft delete | `deleted_at` timestamp column set to NOW(); partial indexes exclude tombstoned rows. No v1 write path touches `deleted_at` — see §16. |
| `scan_job` | No soft delete | Terminal statuses (COMPLETED, SUPERSEDED, FAILED) serve as the historical record. No `deleted_at` column. |
| `user_report` | Soft delete | `deleted_at` timestamp column (V14); partial indexes exclude tombstoned rows. No v1 write path touches `deleted_at` — see §16. |
| `report_job` | Retained | Rows are never deleted in v1; PDF BLOB is cleaned up in v2 via filesystem offload. |
| `share_link` | Logical revoke + TTL cleanup | `is_revoked = TRUE` for explicit revocation; expired rows are purged by the maintenance batch (§21a — at startup and every 24 h via the in-process timer). CASCADE deleted when parent `report_job` is purged. |
| `idempotency_key` | Hard delete (TTL) | Deleted after 24 h TTL by the maintenance batch (§21a — at startup and every 24 h via the in-process timer). |
| `password_reset_token` | Hard delete (TTL) | Deleted after successful reset or after the 1-hour expiry. |
| `audit_log` | Never deleted | Retained indefinitely for compliance and forensics. `actor_id` is set NULL on user deletion; `actor_username` retains the `deleted_{uuid}` tombstone. |
| `api_token` | CASCADE on user delete | No independent delete path in v1; CASCADE DELETED when `secbret_user` is hard-deleted. |
| `webhook_subscription` | CASCADE on user delete | No v1 write path; CASCADE DELETED on user deletion. |

See `Part IV` §ON DELETE Cascade Policy for the full FK cascade chain, and §V20 for the GDPR tombstone trigger DDL.

---

## G. Enumerations

The SecBret specification set centralizes all enumerations in `Part III` §Enumerations. This section lists the canonical values for cross-reference.

**Roles**

| Role | Key |
|------|-----|
| `REPORTER` | Authenticated read-only / submit own scans |
| `ANALYST` | Can manage jobs, review incidents, mark escalations |
| `ADMIN` | Full access including user management and incident resolution |

> `ANONYMOUS` is not a persisted role value. It appears in the RBAC permission matrix
> (§4) only to denote endpoints that permit unauthenticated access. The `secbret_user.role`
> column only stores `REPORTER`, `ANALYST`, or `ADMIN` — enforced by `chk_user_role`.

**Scan State**

| State | Meaning |
|-------|---------|
| `PENDING` | Job queued but not yet started |
| `RUNNING` | Actively scanning |
| `FAILED` | Scan ended with an error |
| `COMPLETED` | Scan succeeded; results available |
| `SUPERSEDED` | Replaced by a newer scan for the same URL before or during execution; `supersededBy` field points to the replacement job |

**Report Generation State**

| State | Meaning |
|-------|---------|
| `PENDING` | Report queued |
| `GENERATING` | PDF being produced |
| `COMPLETED` | Report ready for download |
| `FAILED` | PDF generation failed |

**Incident (Report) State**

| State | Meaning |
|-------|---------|
| `PENDING` | Submitted; SecBret async analysis not yet run |
| `PENDING_REVIEW` | AI analysis complete; score in uncertain zone; awaiting human analyst |
| `VERIFIED` | Incident resolved — either auto-approved/rejected by AI or confirmed by human review |
| `REJECTED` | Report rejected by security team; community verdict unchanged |
| `FAILED` | Async analysis DB write failed (terminal); user must re-submit |

All enumeration values are defined exactly in `openapi.yaml` and `Part III`. When adding new values, add to the end of the list to preserve backward compatibility; do not change existing values.

## 1. Architectural Decisions

Summary of the decisions that shaped v1. Where a decision has its own ADR, the ADR carries the long-form context; the table below is the condensed reference.

A recurring theme worth stating up front: **SecBret is a low-scale, single-instance system.** A lot of these choices (in-process queue, in-memory rate limiting, no external cron) only make sense under that assumption. See §14 and the assumptions called out throughout §6. If the scale assumption ever breaks, most of this table gets revisited.

| # | Decision Area | Choice | Rationale |
|---|---------------|--------|-----------|
| 1 | **SecBret AI Engine** | Hybrid: Java rules + Python ML sidecar (gRPC) | Rules handle common patterns transparently; ML covers edge cases via separate service |
| 2 | **Scan History** | True overwrite: one job per URL at a time | Simplifies data model and UX; reduces storage; partial unique index enforces at DB level. Supersede-then-insert must be inside a single `@Transactional` boundary to maintain the one-active-job invariant. **Race condition fix (C2 — two layers):** (a) `ScanPersistence.createJob()` acquires a row-level lock with `SELECT * FROM scanned_url WHERE id = :urlId FOR UPDATE` before any scan_job read or write, serialising all concurrent submits for the same URL. (b) The `superseded_by` back-pointer is set atomically by the V20 `link_superseded_scan_job` AFTER INSERT trigger — not by application step 4. This means the back-pointer is set unconditionally regardless of whether application code runs step 4 or not; `ScanPersistence.createJob()` must remove its explicit step-4 UPDATE to avoid dead code. The `ConstraintViolationException` catch on `uq_scan_job_active_per_url` is retained only as a last-resort safety net (must log ERROR, not silently swallow). **Code review checklist:** verify step 4 is absent from `ScanPersistence.createJob()`. **Required unit test:** assert that after a supersede-then-insert cycle, `superseded_by` is set on the old job without any application-level UPDATE — i.e. only the trigger may write this field. |
| 21a | **Maintenance Carve-Out** | Startup batch + recurring 24 h in-process timer for idempotency_key and share_link | Exception to #21. The batch runs once at application startup **and every 24 h thereafter** via its own `@Singleton @Startup` `TimerService` bean — no external cron. This is a **separate bean from the §5 rate-limit eviction sweep**: both use the same in-process `TimerService` mechanism, but they are two independent timers with independent periods (maintenance batch = fixed 24 h; §5 eviction sweep = `window × 2`, i.e. ≤ 2 h). It hard-deletes `idempotency_key` rows past their 24 h TTL and purges expired `share_link` rows. The recurring timer means a long-running instance reclaims expired rows without requiring a restart. |
| 3 | **PDF Generation** | Async with polling | Avoids blocking request threads on complex PDF rendering |
| 4 | **PDF Layout** | 3-page condensed | Faster generation, sufficient for executive + key findings |
| 5 | **Scan Depth** | User-selectable: Quick (T1) or Deep (T1+T2+T3) | User controls scan depth per submission |
| 6 | **Scale Target** | Low (10-100 scans/day) | Single Payara instance; in-process queue sufficient |
| 7 | **Authentication** | Soteria + DB identity store | No external identity provider needed |
| 8 | **Rate Limiting** | Interface-based Servlet Filter (ConcurrentHashMap) | Single-instance deployment; in-memory tracking via ConcurrentHashMap is sufficient with zero external dependencies |
| 9 | **Job Queue** | `@ManagedExecutorService` | In-process; appropriate for low scale and single instance |
| 10 | **DB Migrations** | Flyway | SQL-based, mature, excellent Hibernate/JPA compatibility |
| 11 | **UUID Share Links** | Configurable expiry (default 30 days) | Prevents stale data circulation; user can revoke |
| 12 | **Testing** | Unit (JUnit5+Mockito) + Integration (Testcontainers) | Good coverage without E2E maintenance burden |
| 13 | **PDF Storage** | Database BLOB (PostgreSQL BYTEA) | Eliminates Docker volume, filesystem path management, and path traversal defense; transactional consistency; ~25 MB/month at stated scale |
### BLOB Storage Considerations

`report_job.file_data` is stored as `BYTEA`. Due to PostgreSQL MVCC, updating the row (e.g., PENDING → GENERATING → COMPLETED) creates multiple tuple versions. The BLOB data is TOASTed, so only the TOAST pointer is duplicated until the row is updated, but the full BLOB is copied on any update that changes it.

**Mitigation:**
- `report_job` rows should only have `file_data` set on the final COMPLETED update, never on intermediate states.
- Run `VACUUM` regularly on the `report_job` table.
- Consider table partitioning by `created_at` for long-term retention.

**v2 Path:** Offload PDF storage to filesystem or S3-compatible object storage.

| 14 | **Observability** | SLF4J structured JSON logging | Sufficient for low scale; can add Micrometer later if needed |
| 15 | **Tier 4 Sandbox** | Future enhancement only | Focus resources on Tier 1-3; avoid Docker-in-Docker complexity |
| 16 | **ML Integration** | Python sidecar (HTTP/gRPC) | Clean separation; independent scaling/deployment; language-appropriate for ML |
| 17 | **Scan Failure** | Mark FAILED, log, no retry | Simplest; user resubmit if needed; avoids retry loops on dead URLs |
| 18 | **Maven Modules** | Monolithic WAR (single module) | Fits low scale; simplest build/deploy; no multi-module overhead |
| 19 | **Frontend** | JSP + HTMX + Bootstrap | Server-rendered with dynamic partials; no SPA complexity; fits Jakarta MVC |
| 20 | **Deployment** | Docker Compose (Payara + PostgreSQL + Python sidecar) | Reproducible; single `docker-compose up` for full stack |
| 21 | **Scheduled Tasks** | No external cron; in-process timers only (with carve-out) | No OS cron / external scheduler. The only scheduled work is **two independent** in-process `TimerService` beans: (1) the §5 rate-limit eviction sweep (startup + every `window × 2`) and (2) the #21a maintenance batch (startup + every 24 h) cleaning idempotency_key (24 h TTL) and expired share_link rows |
| 22 | **Web Hardening** | CORS + CSP + HSTS + X-Frame-Options + CSRF | Defense-in-depth at web layer |

---

## 2. Technology Stack

Versions below are the floor we build and test against, not exact pins — the `+` suffix means "this or newer within the same major." The one place we care about an exact major is PostgreSQL 14 (see ADR-0007); everything else tracks the latest patch of its major line.

### Core Platform
| Technology | Version | Purpose |
|------------|---------|---------|
| Jakarta EE | 10 | Enterprise platform |
| Payara | 6.2023+ | Application server |
| Jakarta MVC (Krazo) | 3.x | Server-side MVC for web UI |
| Jakarta REST (JAX-RS) | 3.x | REST API |
| Jakarta Persistence (JPA) | 3.1 | ORM with Hibernate 6 |
| Jakarta Security (Soteria) | 3.x | Authentication & RBAC |
| Jakarta Concurrency | 2.x | Async scan/report execution |
| Jakarta CDI | 4.x | Dependency injection, events |
| Jakarta Bean Validation | 3.x | Input validation |
| Jakarta Servlet | 6.x | Filters (rate limit, security headers) |

### Libraries
| Library | Version | Purpose |
|---------|---------|---------|
| jsoup | 1.17+ | HTML parsing for Tier 2 active scanning |
| OpenPDF | 2.0+ | PDF report generation (3-page condensed) |
| Flyway | 10.x | Database schema migration |
| BCrypt (via Soteria) | - | Password hashing |
| SLF4J + Logback | 1.4+ / 1.4+ | Structured JSON logging |
| gRPC Java | 1.60+ | Communication with Python ML sidecar |
| Jakarta Mail (Angus Mail) | 2.0+ | SMTP email dispatch (password reset) |
| JUnit 5 | 5.10+ | Unit testing |
| Mockito | 5.x | Mocking for unit tests |
| Testcontainers | 1.19+ | Integration testing with real PostgreSQL |
| AssertJ | 3.24+ | Fluent test assertions |
| Hibernate Validator | 8.x | Bean Validation provider |

### Infrastructure
| Component | Version | Purpose |
|-----------|---------|---------|
| PostgreSQL | 14+ | Primary relational database |
| Python | 3.11+ | ML sidecar service |
| gRPC | - | Inter-service communication (Java ↔ Python) |
| Docker | 24+ | Container runtime |
| Docker Compose | 2.x | Multi-container orchestration |
| Maven | 3.9+ | Build tool |

---

## 3. MVC Architecture (Jakarta MVC / Krazo)

### Controller → View → Model Mapping

```
┌──────────────────────────────────────────────────────────────┐
│                    CONTROLLERS (Jakarta MVC)                   │
├──────────────────────────────────────────────────────────────┤
│                                                                │
│  Web Controllers (Krazo @Controller + JSP views)              │
│  ┌───────────────────┐  ┌──────────────────────┐              │
│  │ DashboardController│  │ ReportController     │              │
│  │ GET  /             │  │ GET  /share/{uuid}   │              │
│  │ GET  /dashboard    │  │   (shared report)    │              │
│  │ GET  /scan/{id}    │  └──────────────────────┘              │
│  └───────────────────┘  ┌──────────────────────┐              │
│  ┌───────────────────┐  │ AdminWebController   │              │
│  │ IncidentWebCtrl   │  │ GET  /admin/reviews  │              │
│  │ GET  /report/new  │  │ POST /admin/reviews/ │              │
│  │ POST /report/submit│  │ GET  /admin/users     │              │
│  └───────────────────┘  │ PUT  /admin/users/    │              │
│  ┌───────────────────┐  │ POST /admin/users/    │              │
│  │ ScanWebController  │  └──────────────────────┘              │
│  │ GET  /scan/new     │                                        │
│  │ POST /scan/submit │                                        │
│  └───────────────────┘                                        │
│  ┌───────────────────┐                                        │
│  │ AuthWebController  │                                        │
│  │ GET  /login        │                                        │
│  │ POST /login        │                                        │
│  │ POST /register     │                                        │
│  │ POST /logout       │                                        │
│  └───────────────────┘                                        │
│                                                                │
│  REST Controllers (JAX-RS @Path + JSON)                        │
│  ┌───────────────────┐  ┌──────────────────────┐              │
│  │ ScanResource       │  │ IncidentResource      │              │
│  │ POST /api/v1/scan  │  │ POST /api/v1/incident│              │
│  │ GET  /api/v1/scan/ │  │ GET  /api/v1/incident/│              │
│  │ GET  /api/v1/scan  │  └──────────────────────┘              │
│  └───────────────────┘  ┌──────────────────────┐              │
│  ┌───────────────────┐  │ ReportJobResource    │              │
│  │ AuthResource       │  │ POST /report-jobs/*  │              │
│  │ DELETE /auth/me    │  │ GET  /report-jobs/*  │              │
│  │  (GDPR only)       │  └──────────────────────┘              │
│  └───────────────────┘  ┌──────────────────────┐              │
│  │ AdminResource       │  │ ShareResource        │              │
│  │ GET  /api/v1/admin/ │  │ GET  /share/{uuid}   │              │
│  │ POST /api/v1/admin/ │  │ DELETE /share/{uuid} │              │
│  └───────────────────┘  │ POST /share          │              │
│                         │ GET  /share          │              │
│                         └──────────────────────┘              │
│                         ┌──────────────────────┐              │
│                         │ HealthResource       │              │
│                         │ GET  /health/live    │              │
│                         │ GET  /health/ready   │              │
│                         │ GET  /health/dependencies │              │
│                         │   (no auth required) │              │
│                         └──────────────────────┘              │
│                                                                │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                    SERVICE LAYER (CDI Beans)                    │
│  ScanService (→ScanPersistence) │ IncidentService             │
│  ThreatAnalyzer │ SecurityTeamReviewService                   │
│  ReportGenerationService │ UserService │ ShareLinkService     │
│  EmailService          │ AuditLogService                     │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                    REPOSITORY LAYER (JPA)                       │
│  ScannedUrlRepository │ ScanJobRepository │ ScanResultRepo   │
│  UserReportRepository │ SecBretAnalysisRepository           │
│  SecurityTeamReviewRepository │ ReportJobRepository           │
│  ShareLinkRepository │ UserRepository                          │
└──────────────────────────────────────────────────────────────┘
```

### JSP View Structure

```
WEB-INF/views/
├── layout/
│   └── default.jsp          (HTMX + Bootstrap base layout)
├── auth/
│   ├── login.jsp            (Login form)
│   └── register.jsp         (Registration form)
├── dashboard/
│   ├── public.jsp            (Public dashboard - no auth)
│   └── home.jsp             (Authenticated user home)
├── scan/
│   ├── new.jsp               (Submit scan form)
│   ├── status.jsp            (Scan job status - HTMX polling)
│   └── result.jsp            (Scan result details)
├── incident/
│   ├── new.jsp               (Report incident form)
│   ├── list.jsp              (My incident reports)
│   └── detail.jsp            (Incident detail + SecBret analysis)
├── report/
│   ├── generate.jsp          (Generate report request)
│   ├── status.jsp            (Report job status - HTMX polling)
│   └── shared.jsp            (Shared report view via UUID)
└── admin/
    ├── reviews.jsp           (Pending review queue)
    ├── review-detail.jsp     (Full review + approve/reject form)
    └── users.jsp             (User management table)
```

### HTMX Interaction Patterns

| Pattern | Implementation |
|---------|---------------|
| **Scan polling** | `<div hx-get="/scan/status/{jobId}" hx-trigger="every 3s" hx-swap="innerHTML" hx-target="#poll-status">` — a static container owns the `hx-*` attributes; fragments swap into an inner target so the polling element survives every swap. The polling element MUST NOT self-swap with `hx-swap="outerHTML"` (fragments do not re-emit the `hx-*` attributes, so the first swap would silently kill polling). |
| **Report / incident polling** | Same container pattern for `/report/status/{jobId}` and `/incident/{id}/status-fragment`. |
| **Polling stop signal** | Server returns `HX-Trigger: stopPolling` **and** `HX-Refresh: true` response headers on terminal status (`COMPLETED` / `FAILED` / `SUPERSEDED`). htmx reloads the page, which renders the terminal state server-side; a global `htmx:afterRequest` listener in `secbret.js` also unwraps the polling element as belt-and-braces. |
| **No inline `hx-on`** | Inline `hx-on::*` attributes are FORBIDDEN: htmx evaluates them with `eval()`, which the CSP (`script-src 'self' 'nonce-…'`, ADR-0004) blocks — handlers silently never run. All htmx event handling lives in `static/js/secbret.js` (nonce-loaded) as `document.body` listeners. |
| **Submit forms** | `hx-post="/scan/submit" hx-target="#result" hx-swap="innerHTML"` |
| **Pagination** | `hx-get="/admin/reviews?page=2" hx-target="#review-list" hx-push-url="true"` |
| **Inline updates** | Approve/reject buttons: `hx-post="/admin/reviews/{id}" hx-target="#review-{id}"` |
| **Toasts** | Global `showToast` listener on `HX-Trigger: {"showToast": …}` events (secbret.js §3). |

---

## 4. RBAC Model

### Role Permission Matrix

| Resource / Action | ANONYMOUS | REPORTER | ANALYST | ADMIN |
|-------------------|-----------|----------|---------|-------|
| View public dashboard | ✓ | ✓ | ✓ | ✓ |
| Access shared report link | ✓ | ✓ | ✓ | ✓ |
| Register / Login | ✓ | ✓ | ✓ | ✓ |
| Submit URL scan | - | ✓ | ✓ | ✓ |
| View own scan results | - | ✓ | ✓ | ✓ |
| Submit incident report | - | ✓ | ✓ | ✓ |
| View own incident reports | - | ✓ | ✓ | ✓ |
| Generate PDF report | - | ✓ | ✓ | ✓ |
| Create share links | - | ✓ (own) | ✓ | ✓ |
| **Revoke share links** | - | **✓ (own)** | **✓ (all)** | **✓ (all)** |
| View all scan results (`?all=true`) | - | - | ✓ | ✓ |
| View pending review queue | - | - | ✓ | ✓ |
| Approve/reject incidents | - | - | ✓ | ✓ |
| List/manage users | - | - | - | ✓ |
| Change user roles | - | - | - | ✓ |
| Enable/disable users | - | - | - | ✓ |
| Delete own account (GDPR) | - | ✓ | ✓ | ✓ |
| Change own password | - | ✓ | ✓ | ✓ |

#### Fine-Grained Ownership Restrictions

In addition to the matrix, the following endpoint-level restrictions apply:

- **`GET /api/v1/scan/url/{urlId}`:** REPORTERs may only view URLs for which they have previously submitted at least one scan job (any historical `scan_job` with matching `url_id` and `submitted_by = userId`, including superseded jobs). Unauthorized access returns 404.
- **`GET /api/v1/scan` with `?all=true`:** Only ANALYST and ADMIN may set `all=true`. REPORTERs receive 403.
- **`GET /api/v1/incident` with `?all=true`:** Only ANALYST and ADMIN may set `all=true`. REPORTERs receive 403.
- **`POST /api/v1/share`:** REPORTERs may only create share links for report jobs where `requested_by` equals their own user ID.
- **`DELETE /api/v1/share/{uuid}`:** REPORTERs may only revoke share links they created.
- **`PUT /api/v1/admin/users/{userId}/status`:** ADMINs may not disable their own account (returns 409 Conflict).

### Implementation via Soteria

```java
@ApplicationScoped
public class SecBretIdentityStore implements IdentityStore {

    @Inject UserRepository userRepo;

    @Override
    public CredentialValidationResult validate(Credential credential) { ... }

    @Override
    public Set<ValidationType> validationTypes() {
        return EnumSet.of(ValidationType.VALIDATE, ValidationType.PROVIDER_GROUPS);
    }
}
```

`validate()` checks the submitted username/password against the DB via `UserRepository` and, on success, returns a `CallerPrincipal` carrying the user's role group.

### Annotation-Based Authorization

Authorization is annotation-driven: `@RolesAllowed` on the MVC web controllers, and `@RolesAllowed` / `@PermitAll` on the JAX-RS resources.

```java
@RolesAllowed({"REPORTER", "ANALYST", "ADMIN"})
public class ScanWebController { ... }

@RolesAllowed({"ANALYST", "ADMIN"})
public class AdminWebController { ... }

@PermitAll
public class PublicDashboardResource { ... }

@RolesAllowed("ADMIN")
public class AdminResource { ... }
```

---

## 5. Security Hardening

### Security Headers Filter

All responses include:

| Header | Value | Purpose |
|--------|-------|---------|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self' 'nonce-{REQUEST_NONCE}'; style-src 'self' 'nonce-{REQUEST_NONCE}'; img-src 'self' data:` | XSS prevention with per-request nonces. Strict `'self'` — Bootstrap/HTMX are self-hosted (`static/js`, `static/css`), no CDN origins (see ADR-0004) |
| `X-Frame-Options` | `DENY` | Clickjacking prevention |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing prevention |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Force HTTPS |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limit referrer leakage |

### CORS Configuration

```
Allowed Origins: Same origin + configured whitelist
Allowed Methods: GET, POST, PUT, DELETE
Allowed Headers: Content-Type, Authorization, X-Requested-With
Allow Credentials: true
Max Age: 3600s
```

In practice the UI is served from the same origin as the API, so CORS is mostly moot for the shipped product — the whitelist (`CORS_ALLOWED_ORIGINS`) exists for the occasional external integration and stays empty by default. We deliberately did **not** wildcard the origin: `Allow Credentials: true` with `*` is both disallowed by the spec and a footgun, so any cross-origin caller has to be named explicitly.

### CSRF Protection

SecBret implements CSRF protection at two layers: **Jakarta MVC web UI** and **JAX-RS API**.

**Jakarta MVC / JSP Layer (Web UI)**

Krazo generates a per-session CSRF token stored in the HTTP session. All state-changing JSP forms include the token via `${_csrf.token}`:

```jsp
<form action="/scan/submit" method="post">
    <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
</form>
```

On form submission, Krazo validates the submitted token against the session. Mismatch results in `403 Forbidden`. The session token is regenerated on successful login to prevent fixation attacks.

**JAX-RS API Endpoints**

Because authentication is cookie-based, authenticated state-changing requests remain vulnerable to CSRF.

All POST, PUT, PATCH and DELETE endpoints require:
- Valid authenticated session
- Valid `X-CSRF-Token` header

Session cookies SHALL be:
- `HttpOnly`
- `Secure`
- `SameSite=Strict`

Missing or invalid CSRF token SHALL return HTTP 403.

**Public Read-Only Endpoints**

The following endpoints are exempt from CSRF entirely (no session auth required):
- `GET /api/v1/health/live`, `GET /api/v1/health/ready`, `GET /api/v1/health/dependencies` — health probes
- `GET /dashboard/public` — public dashboard
- `GET /api/v1/share/{uuid}` — shared report access

### Scanner Safety

| Safety Measure | Implementation |
|---------------|----------------|
| **SSRF / private-IP block** | Deny-by-default: resolve the host and validate **every** A/AAAA address against the reserved deny-set, pin-and-connect to a validated IP, and re-validate on every redirect hop. See **SSRF Hardening** below. |
| **Connection timeout** | 5 seconds connect, 5 seconds read |
| **Max redirects** | 3 redirects max |
| **Response size limit** | 5MB max for Tier 2 HTML fetch |
| **No JS execution** | jsoup parsing only; no JavaScript engine |
| **URL length limit** | Max 2048 characters |

#### SSRF Hardening (B3)

Validating the literal hostname string is **not** sufficient. The URL validator MUST defend against DNS-rebinding, redirect-based, and encoding-based SSRF bypasses:

1. **Deny-by-default address validation.** Resolve the host and reject the request unless **all** returned A/AAAA records fall outside the reserved ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16` (link-local, incl. cloud metadata `169.254.169.254`), `0.0.0.0/8`, `100.64.0.0/10` (CGNAT), `::1`, `::`, `fc00::/7` (ULA), `fe80::/10` (link-local), and IPv4-mapped IPv6 `::ffff:0:0/96`. A single private address in the result set rejects the whole URL.
2. **Pin-and-connect (TOCTOU / DNS-rebinding defense).** Connect to the exact IP that was validated; do **not** re-resolve the hostname between validation and the socket connect. Re-resolution lets a rebinding attacker return a public IP during validation and a private IP at connect time.

   For `https` targets, pinning MUST NOT weaken TLS. The contract is **pin the transport, verify the hostname**:
   - The TCP socket MUST connect to the **validated IP literal**.
   - The TLS handshake MUST present the **original hostname** (never the IP) in the SNI `server_name` extension, so name-based virtual hosts serve the correct certificate.
   - Certificate validation MUST chain-validate against the trust store **and** verify the certificate's identity against the **original hostname** (HTTPS endpoint identification per RFC 6125/9110 rules) — the certificate must match the hostname, NOT the pinned IP. Certificate or hostname verification MUST NOT be disabled, relaxed, or replaced with an accept-all trust manager / hostname verifier to make IP-pinning work; a pin-and-connect implementation that turns off endpoint identification is non-conformant.
   - **Mechanism (implementable contract).** In Java terms: open the socket to the pinned IP, layer the `SSLSocket` over it, set `SNIHostName(originalHost)` via `SSLParameters.setServerNames(...)`, and enable hostname verification for the original host by setting the endpoint-identification algorithm to `"HTTPS"` (or an equivalent `HostnameVerifier` bound to the hostname). The `Host` request header likewise carries the original hostname. An equivalent mechanism — e.g. an HTTP-client DNS-resolver override that returns the pinned IP for exactly that hostname for the lifetime of the request — satisfies the contract, provided SNI and certificate identity always use the hostname.
   - On **every redirect hop**, the new `Location` host is resolved and validated fresh (item 3), and this same pin-and-connect + SNI/hostname-verification contract reapplies to the new host and its newly pinned IP.
3. **Re-validate every redirect hop.** Each 3xx `Location` is a new URL; apply the full validation (scheme, host, resolved-IP deny-set) to every hop, up to the 3-redirect cap.
4. **Normalize address encodings before validation.** Canonicalize or reject integer (`http://2130706433/`), octal (`0177.0.0.1`), hex (`0x7f.0.0.1`), and shorthand (`127.1`) IP encodings; validate the canonical form.
5. **Scheme allowlist.** Only `http` and `https` are permitted at submission and at every redirect hop — never `file:`, `gopher:`, `ftp:`, or `dict:`.

Required tests: DNS-rebinding (validation IP public, connect IP private), redirect-to-`169.254.169.254`, integer/octal/hex-encoded localhost, and `file://`-scheme redirect — each MUST be rejected. The TLS pin-and-connect contract MUST additionally be tested: a server presenting a certificate valid for the **hostname**, while the connection is pinned to the validated public IP, MUST succeed; a certificate whose identity does not match the hostname MUST be rejected; and the test MUST assert TLS validation is never bypassed (no accept-all trust manager or hostname verifier is reachable on the pinned path).

### Authentication Security

| Measure | Implementation |
|---------|----------------|
| **Account lockout** | 5 failed login attempts → account locked for 15 minutes. Successful login resets the counter to 0 and clears `locked_until`. |
| **Session timeout** | 30 minute idle timeout |
| **Password policy** | See §3 Password Policy. |
| **Password hashing** | BCrypt with cost factor 12 |

> **HIBP fail-open risk acceptance:** If the HIBP API is unreachable or times out (3 s), the check is skipped and registration is allowed (`fail-open`). This is a deliberate tradeoff that prioritises availability over strictness. For a security-oriented platform this is a known risk; operators who require `fail-closed` behaviour must set `HIBP_FAIL_OPEN=false` (planned v2 env var) or block registration behind a secondary check. The current `fail-open` behaviour is a conscious design decision, not an oversight.

### Rate Limiting Implementation

Rate limiting is enforced by a single **Servlet Filter** (`RateLimitFilter`) that is registered for all request paths. At the low scale of a single Payara instance, the implementation stores all state in a **per-JVM `ConcurrentHashMap`** with zero external dependencies.

> **Assumption — single instance.** All of this is per-JVM. There is no shared counter across nodes because there is only ever one node (ADR-0006, §14). The moment SecBret runs behind more than one Payara instance, these limits become per-instance and effectively multiply by the instance count — at which point the honest fix is Redis or a gateway-level limiter, not a distributed cache bolted onto this filter. We're explicitly not paying that complexity now. See §10.5 for the shape v2 would take.
>
> A second consequence worth naming: unauthenticated callers are keyed by client IP, so anything behind a shared NAT or corporate proxy shares a bucket. That's an accepted limitation for login/forgot-password throttling — the alternative (per-account lockout, which we also have) covers the case that actually matters.

**Keying Strategy**

| Endpoint Key | Bucket Key | Scope |
|-------------|-----------|-------|
| `POST /api/v1/scan` | `<userId>` | per user per hour |
| `POST /api/v1/incident` | `<userId>` | per user per hour |
| `POST /api/v1/report-jobs/*` | `<userId>` | per user per hour |
| `POST /api/v1/share` | `<userId>` | per user per hour |
| `POST /login` (web form) | `<clientIp>` | per IP per 15 min |
| `POST /forgot-password` (web form) | `<clientIp>` | per IP per 15 min |
| `POST /reset-password` (web form) | `<clientIp>` | per IP per 15 min |
| `GET /api/v1/dashboard/public` | `<clientIp>` | per IP per minute |
| default (all remaining) | `<clientIp>` | per IP per minute |
| auth-backstop (auth surface, checked before the fine-grained rule) | `<clientIp>` | per IP per hour, 100 default (`RATE_LIMIT_AUTH_BACKSTOP`) |

**Auth surface (backstop coverage):** every request under the `/auth/` REST prefix, plus `POST` to the web-form auth endpoints `/login`, `/register`, `/forgot-password`, `/reset-password` (which are served at the root by Jakarta MVC, not under `/auth/`). GETs of the form pages are covered by the default per-minute rule only, so page loads behind a shared NAT are not throttled by the backstop.

Authenticated requests are keyed by the authenticated user ID (taken from `Principal.getName()`). Unauthenticated requests are keyed by the `X-Forwarded-For` (if present) or `REMOTE_ADDR`.

**Bucket Structure** (`RateLimitBucket`)
- `capacity` — maximum tokens allowed in the window
- `windowMillis` — duration of the rate-limit window
- `double addStampedeTokens` — on a burst window start, this bucket refills `capacity` × `stampedeThreshold` tokens; default `stampedeThreshold = 0.30` (30%)
- `tokens` — current available tokens (floating-point)
- `lastRefill` — timestamp of the last token refill
- `Atomic update` — all reads and writes to the bucket use `ConcurrentHashMap.compute` for thread-safe, consistent updates

**Stampede Protection**
- On window start (first request), the bucket receives `capacity × 0.30` tokens
- This prevents bursty "Reopen" floods (e.g., after a restart) from exhausting the entire bucket in the first few seconds

**Bucket Eviction**

Expired buckets are evicted during the `ConcurrentHashMap.compute` call triggered by the next request from the same key. If a key has been idle for more than `windowMillis` since `lastRefill`, the compute lambda treats it as a fresh bucket (re-initialising `tokens` and `lastRefill`) rather than accumulating stale tokens. Additionally, a background eviction sweep runs at Payara startup and every `window × 2` thereafter via a `@Singleton @Startup` `TimerService` bean, removing all map entries whose `lastRefill + windowMillis < now`. This bounds the map to the set of recently active callers and prevents unbounded growth during long-running deployments.

**Response on Rate Limit Exceeded**

All responses include rate limit headers (even when not exceeded):
```
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 7
X-RateLimit-Reset: 1718618400
```

When the bucket is exhausted, the filter returns **429 Too Many Requests** with a JSON error body and a `Retry-After` header:
```json
{
  "status": 429,
  "error": "Too Many Requests",
  "message": "Rate limit exceeded. Retry after 2026-06-22T14:00:00Z.",
  "timestamp": "2026-06-22T14:00:00Z",
  "path": "/api/v1/scan"
}
```
The `Retry-After` header is an integer of seconds until the next window begins.

**JAX-RS / MVC Coordination**

The servlet filter runs *before* any `@PermitAll` / `@RolesAllowed` security check. If the rate limit is exceeded, the request is blocked before reaching the authentication layer (preventing auth load during a DDoS).

---

## 6. Deployment Architecture (Docker Compose)

The whole system comes up with a single `docker-compose up`: Payara, PostgreSQL, the Python ML sidecar, and a small backup sidecar. That's the entire deployment story for v1, and it's a deliberate ceiling — see ADR-0006.

**Why Compose and not Kubernetes.** For a single-node, 10–100-scans/day system, k8s buys us orchestration we don't need and a large operational surface we'd have to learn and babysit. Compose gives reproducible local + single-host deploys with almost no ceremony. The trade-off we're accepting: no rolling deploys, no self-healing beyond `restart: unless-stopped`, and horizontal scale-out is not a thing this topology does. If any of those become requirements, this section is where the rewrite starts — but nothing below assumes we'll ever need them.

**Operational assumptions.** One host, operator has shell access, backups land on that host's filesystem (`./backups`) and are somebody's responsibility to ship off-box — Compose doesn't do that for you. Secrets come from `.env` on the host; there's no secret manager in v1.

### docker-compose.yml Structure

```yaml
services:
  postgres:
    image: postgres:14-alpine
    environment:
      POSTGRES_DB: ${POSTGRES_DB}
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - pg_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $$POSTGRES_USER -d $$POSTGRES_DB"]
      interval: 5s
      timeout: 5s
      retries: 10
      start_period: 10s

  secbret-ml:
    build: ./ml-sidecar
    ports: ["50051:50051"]
    volumes:
      - ./ml-sidecar/model:/app/model
    healthcheck:
      test: ["CMD", "python", "-c",
             "import grpc; ch=grpc.insecure_channel('localhost:50051'); grpc.channel_ready_future(ch).result(timeout=2)"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 15s

  payara:
    build: .
    ports: ["8080:8080"]
    env_file: .env
    depends_on:
      postgres:
        condition: service_healthy
      secbret-ml:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:8080/api/v1/health/ready || exit 1"]
      interval: 15s
      timeout: 5s
      retries: 5
      start_period: 30s
    restart: unless-stopped

  db-backup:
    image: postgres:14-alpine
    environment:
      PGPASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - ./backups:/backups
    depends_on:
      postgres:
        condition: service_healthy
    entrypoint: >
      sh -c "while true; do
        pg_dump -h postgres -U $$POSTGRES_USER $$POSTGRES_DB
          | gzip > /backups/secbret_$$(date +%Y%m%d_%H%M%S).sql.gz;
        find /backups -name '*.sql.gz' -mtime +$${BACKUP_RETENTION_DAYS:-7} -delete;
        sleep 86400;
      done"
    restart: unless-stopped

volumes:
  pg_data:
```

### Container Details

| Container | Image | Ports | Volumes | Depends On |
|-----------|-------|-------|---------|------------|
| **payara** | Custom (Payara 6 + WAR) | 8080:8080 | (none) | postgres (healthy), secbret-ml (healthy) |
| **postgres** | `postgres:14-alpine` | (no host port) | `pg_data:/var/lib/postgresql/data` | - |
| **secbret-ml** | Custom (Python 3.11 + gRPC) | 50051:50051 | `./ml-sidecar/model:/app/model` | - |
| **db-backup** | `postgres:14-alpine` | (none) | `./backups:/backups` | postgres (healthy) |

### Environment Variables

| Variable | Container | Description | Default |
|----------|-----------|-------------|---------|
| `DB_URL` | payara | JDBC connection string | `jdbc:postgresql://postgres:5432/secbret` |
| `DB_USER` | payara | Database username | `secbret` |
| `DB_PASSWORD` | payara | Database password | (required) |
| `SCAN_TIMEOUT_MS` | payara | HTTP request timeout | `5000` |
| `SCAN_MAX_REDIRECTS` | payara | Max HTTP redirects | `3` |
| `SCAN_MAX_RESPONSE_BYTES` | payara | Max Tier 2 response | `5242880` (5MB) |
| `AUTO_APPROVE_HIGH` | payara | Score ≥ for auto-approve; also the (exclusive) upper bound of the ML consultation band | `0.95` |
| `AUTO_APPROVE_LOW` | payara | Score ≤ for auto-reject; also the (exclusive) lower bound of the ML consultation band | `0.05` |
| `ML_SIDECAR_HOST` | payara | ML sidecar address | `secbret-ml:50051` |
| `RATE_LIMIT_SCAN` | payara | Max scans per user per hour | `10` |
| `RATE_LIMIT_REPORT` | payara | Max incident reports per user/hour | `5` |
| `RATE_LIMIT_PDF_REPORT` | payara | Max PDF report-generation jobs per user/hour | `3` |
| `RATE_LIMIT_SHARE` | payara | Max share-link creations per user/hour | `10` |
| `RATE_LIMIT_LOGIN` | payara | Max `POST /login` per IP per 15 min | `10` |
| `RATE_LIMIT_FORGOT` | payara | Max `POST /forgot-password` per IP per 15 min | `5` |
| `RATE_LIMIT_RESET` | payara | Max `POST /reset-password` per IP per 15 min | `5` |
| `RATE_LIMIT_PUBLIC` | payara | Max `GET /dashboard/public` per IP per minute | `60` |
| `RATE_LIMIT_DEFAULT` | payara | Default limit for all other endpoints per IP per minute | `60` |
| `RATE_LIMIT_AUTH_BACKSTOP` | payara | Coarse per-IP backstop on the auth surface per hour (see §5) | `100` |
| `SHARE_DEFAULT_EXPIRY_DAYS` | payara | Default share-link expiry (auto-created links) | `30` |
| `SHARE_MAX_EXPIRY_DAYS` | payara | Maximum share-link lifetime a caller may request | `365` |
| `APP_BASE_URL` | payara | Public base URL used to build shareable links | `http://localhost:8080` |
| `SMTP_HOST` | payara | Mail server hostname | (required) |
| `SMTP_PORT` | payara | Mail server port | `587` |
| `SMTP_TLS` | payara | Enable STARTTLS | `true` |
| `SMTP_USERNAME` | payara | SMTP auth username | (required) |
| `SMTP_PASSWORD` | payara | SMTP auth password | (required) |
| `EMAIL_FROM` | payara | From address for system emails | `noreply@secbret.internal` |
| `HIBP_API_URL` | payara | HIBP k-anonymity API base URL | `https://api.pwnedpasswords.com` |
| `HIBP_TIMEOUT_MS` | payara | HIBP request timeout | `3000` |
| `SEED_ADMIN_USERNAME` | payara | Bootstrap admin username (first-run only) | (optional) |
| `SEED_ADMIN_EMAIL` | payara | Bootstrap admin email (first-run only) | (optional) |
| `SEED_ADMIN_PASSWORD` | payara | Bootstrap admin password (first-run only) | (optional) |
| `BACKUP_RETENTION_DAYS` | db-backup | Days of pg_dump files to keep | `7` |
| `POSTGRES_DB` | postgres | Database name | `secbret` |
| `POSTGRES_USER` | postgres | Database user | `secbret` |
| `POSTGRES_PASSWORD` | postgres | Database password | (required) |

> **Credential coupling (MUST hold):** `DB_USER` = `POSTGRES_USER`,
> `DB_PASSWORD` = `POSTGRES_PASSWORD`, and the database name embedded in
> `DB_URL` = `POSTGRES_DB`. The payara container connects with the `DB_*`
> values to the database the postgres container initializes from the
> `POSTGRES_*` values; if they diverge the app fails at startup with an
> authentication error. `.env.example` sets each pair from a single shared
> value to make divergence impossible by default.
>
> **Canonical env-var list:** this table plus the **Additional Environment
> Variables** table below together define every runtime variable. `.env.example`
> is generated from these two tables and MUST NOT introduce variables that are
> absent here.

### Admin Bootstrap (First-Run Seed)

If `SEED_ADMIN_USERNAME`, `SEED_ADMIN_EMAIL`, and `SEED_ADMIN_PASSWORD` are all set and the `secbret_user` table is empty at application startup, `UserService.seedAdminIfEmpty()` creates one `ADMIN` account using the supplied credentials. The service hashes the raw `SEED_ADMIN_PASSWORD` (via BCrypt) before the `INSERT`; the env var contains the plaintext password, not a pre-computed hash. Subsequent restarts are no-ops (idempotent guard: `SELECT COUNT(*) FROM secbret_user`). Remove these env vars from `.env` after first login.

### Container Resource Limits

| Container | Memory Limit | CPU Limit | JVM/Process Tuning |
|-----------|-------------|-----------|-------------------|
| **payara** | 1 GB | 1.0 | `-Xmx768m -Xms256m -XX:+UseG1GC` |
| **postgres** | 512 MB | 0.5 | `shared_buffers=128MB` |
| **secbret-ml** | 256 MB | 0.5 | Python default |

### Additional Environment Variables

| Variable | Container | Description | Default |
|----------|-----------|-------------|---------|
| `ACCOUNT_LOCKOUT_ATTEMPTS` | payara | Failed logins before lockout | `5` |
| `ACCOUNT_LOCKOUT_DURATION_MIN` | payara | Lockout duration in minutes | `15` |
| `SESSION_TIMEOUT_MIN` | payara | Idle session timeout — *not read from env in v1; fixed in `web.xml` `<session-timeout>` (override via Payara admin)* | `30` |
| `BCRYPT_COST` | payara | BCrypt hashing cost factor | `12` |
| `ML_TIMEOUT_MS` | payara | ML sidecar synchronous call ceiling | `2000` |
| `ML_CB_FAILURE_THRESHOLD` | payara | Circuit-breaker failures before OPEN | `5` |
| `ML_CB_WINDOW_MS` | payara | Circuit-breaker failure-counting window | `60000` |
| `ML_CB_OPEN_MS` | payara | Circuit-breaker OPEN duration before HALF_OPEN | `30000` |
| `AUTO_DECISION_SAMPLE_RATE` | payara | Fraction of auto-decided reports diverted to human audit (B5 calibration loop); clamped to [0.0, 1.0]. ⚠️ Default `0.0` ships the audit loop **off** — see §18 Known Gaps #18; set `0.05`–`0.10` at deployment if dispositive auto-block is enabled. | `0.0` |
| `CORS_ALLOWED_ORIGINS` | payara | Comma-separated extra allowed origins beyond same-origin | (empty) |
| `AUTO_APPROVE_ANALYST_THRESHOLD` | payara | When analyst uses APPROVE, scores ≥ this → VERIFIED_MALICIOUS; below → VERIFIED_BENIGN | `0.50` |

> **Canonical threshold pair.** `AUTO_APPROVE_LOW` / `AUTO_APPROVE_HIGH` (main env
> table above) are the **only** score-boundary variables. The ML consultation band
> is *derived* from the same pair — the open interval
> `(AUTO_APPROVE_LOW, AUTO_APPROVE_HIGH)` — so the §7 alignment invariant ("ML zone
> equals the PENDING_REVIEW band") holds by construction and cannot be
> misconfigured. There are no separate `ML_UNCERTAINTY_*` variables. The rule/ML
> blend weights (`0.4` / `0.6`) are fixed compile-time constants
> (`ThreatAnalyzer.RULE_BLEND_WEIGHT` / `ML_BLEND_WEIGHT`), not env-tunable;
> changing them is a recalibration exercise (see B5 caveat) and requires a
> redeploy by design.

### JDBC Connection Pool Settings

| Setting | Value | Rationale |
|---------|-------|-----------|
| Min pool size | 5 | Warm connections at startup |
| Max pool size | 20 | Fits within PostgreSQL 512MB limit (20 × ~5MB work_mem ≈ 100MB) |
| Connection timeout | 30s | Fails fast on dead connections |
| Idle timeout | 5 minutes | Reclaim unused connections |
| Validation query | `SELECT 1` | Lightweight keep-alive |

> These settings are design recommendations to be applied during implementation.
> Configure in `persistence.xml` or Payara JDBC pool admin.

### Thread Pool and Connection Pool Sizing

| Pool | Size | Rationale |
|------|------|-----------|
| Default ManagedExecutor | 10 | Sufficient for 10-100 scans/day with async PDF/report generation |
| Scan Executor | 5 | Scan operations are I/O bound, not CPU bound |
| Report Executor | 3 | PDF generation is CPU/memory intensive |
| JDBC Max Pool | 20 | 2× total executor threads to prevent queue starvation |

If executor active threads ≥ JDBC max pool / 2, increase pool size or reduce executor thread count.

---

## 7. SecBret AI Engine (Hybrid Rules + ML)

The engine is deliberately split: a **synchronous Java rules engine** that runs on every scan, and a **Python ML sidecar** consulted only for the uncertain middle band. The design rationale is in ADR-0001, but the short version:

- Rules are transparent and cheap. For the common, obvious cases (freshly-registered domain, expired cert, known kit) we get an explainable score with no network hop. Analysts can read a rule score and understand *why*.
- ML earns its keep on the fuzzy cases the rules can't cleanly separate — which is exactly the `PENDING_REVIEW` band, and nowhere else. Consulting it outside that band would spend a 2-second sidecar round-trip on inputs whose disposition is already fixed.

**Alternatives we considered and dropped:**
- *Pure rules, no ML.* Simpler to operate, but recall on novel kits is poor and there's no path to improve it without hand-authoring rules forever.
- *ML-first, rules as a sanity check.* Rejected because it makes every scan depend on the sidecar being up, and it makes verdicts hard to explain to analysts — a non-starter for a tool whose output feeds a human review queue.
- *In-process ML (Java DL4J / ONNX).* Would remove the gRPC hop, but drags the Python ML ecosystem into the JVM build and couples model iteration to app redeploys. The sidecar keeps model rollout independent (swap the container, §ML Model Version Tracking).

The cost of the split is real and we accept it: a second language/runtime, a gRPC contract to keep in sync, and a circuit breaker to stop a sick sidecar from stalling scans. The fail-safe posture (below) is what makes that cost tolerable — an ML outage degrades toward human review, never toward a wrong automated verdict.

### Rules Engine (Java, synchronous)

Runs first for all analyses. Produces a `ruleScore` (0.0-1.0).

| Rule | Weight | Condition |
|------|--------|-----------|
| Domain age | 0.30 | < 7 days = 0.8, < 30 days = 0.5, > 1 year = 0.0 |
| SSL validity | 0.15 | Self-signed = 0.7, expired = 0.9, valid = 0.0 |
| HTTP security headers | 0.10 | Missing CSP+HSTS+XFO = 0.6 |
| Known phishing kit | 0.25 | Detected = 1.0 |
| Suspicious form action | 0.20 | External form post = 0.8 |
| Homoglyph detection | 0.15 | Detected = 0.9 |
| Hidden iframes | 0.10 | Detected = 0.7 |
| Redirect anomalies | 0.05 | > 3 redirects or target differs = 0.5 |

**Score calculation:**

Two-stage evaluation. Stage 1 is a **dispositive override**: a near-certain signal (`knownPhishingKitDetected`, set only by a dispositive-eligible marker match — see Phishing-Kit Marker Governance below) short-circuits scoring to `1.0`. Otherwise Stage 2 applies the normalized weighted average.

```
if knownPhishingKitDetected:
    ruleScore = 1.0
else:
    ruleScore = Σ(weight × ruleValue) / Σ(weights)
```

> **Why the override exists (B1/B2 fix).** The eight weights sum to 1.30 and the
> per-indicator maxima are `{0.8, 0.9, 0.6, 1.0, 0.8, 0.9, 0.7, 0.5}`. The largest
> attainable numerator is therefore `1.075`, so the largest attainable
> **weighted-average** `ruleScore` is `1.075 / 1.30 = 0.827`. Because the ML blend
> is `combined = 0.4·ruleScore + 0.6·mlScore`, even a perfect ML score of `1.0`
> caps `combined` at `0.4·0.827 + 0.6·1.0 = 0.931 < 0.95`. Without the override the
> `VERIFIED_MALICIOUS` auto-action threshold (`≥ 0.95`) is **mathematically
> unreachable**, and a definitive "known phishing kit" hit would be diluted to
> `0.25/1.30 = 0.192`. The dispositive override makes auto-block reachable **only**
> on near-certain evidence — the conservative direction: a false auto-block now
> requires a dispositive signal, never an accumulation of weak ones. The flip
> side is that kit-detector precision becomes single-handedly load-bearing: one
> false marker match auto-publishes `VERIFIED_MALICIOUS` for an innocent site.
> The marker set is therefore governed normatively — see **Phishing-Kit Marker
> Governance (Tier 3 Kit Detection)** below; only markers flagged
> `dispositive-eligible` may fire this override.

> **Note:** The weights above are **unnormalized relative weights**. They sum
> to 1.30, not 1.0. The formula divides by Σ(weights), so normalization is handled
> automatically. Do not interpret the individual weights as direct coefficients
> of a weighted sum that must total 1.0.

> **Reachable-range invariant (required test).** The scoring module MUST ship a
> unit test proving each of the three auto-action verdicts is attainable: (a) a
> dispositive-signal input reaches `combined ≥ 0.95` (`VERIFIED_MALICIOUS`); (b) an
> all-clean input reaches `combined ≤ 0.05` (`VERIFIED_BENIGN`); (c) a mid-range
> input reaches `PENDING_REVIEW`. The same test asserts the **non-dispositive**
> weighted-average path never exceeds `0.827`, guarding against silent
> re-introduction of the unreachable-threshold bug.

### Phishing-Kit Marker Governance (Tier 3 Kit Detection)

The Tier 3 scanner's kit-marker matching is what sets `tier3_findings.knownPhishingKit`, and — via the dispositive override — what auto-publishes `VERIFIED_MALICIOUS`. A single false marker match therefore auto-blocks an innocent site. The marker set is governed by the following normative requirements:

1. **Curated, version-tracked ruleset.** The phishing-kit marker/signature set MUST be a curated, version-tracked artifact with a monotonically increasing versioned identifier (e.g. `2026.07.1`). Every ruleset change MUST be reviewed before it ships; changes that add or promote a **dispositive-eligible** marker (item 2) MUST receive two-person review. Each analysis MUST record the ruleset version that produced it (persisted as `tier3_findings.kitRulesetVersion`; see Part IV) so any verdict is traceable to the exact marker set that triggered it.
2. **Dispositive-eligible flag (precision bar).** Each marker carries an explicit `dispositiveEligible` boolean. Only a match on a dispositive-eligible marker may set `knownPhishingKit = true` and thereby fire the Stage 1 dispositive override. A marker MUST NOT be flagged dispositive-eligible unless it is near-zero-false-positive by construction, qualified by at least one of:
   - an exact match on a kit-unique artifact (file hash, kit-unique path/resource fingerprint, or kit-unique string constant that cannot plausibly occur on a legitimate site), or
   - corroboration by **≥ 2 independent** kit indicators on the same page (independent = derived from different artifacts, not restatements of one signal).

   Weak or heuristic markers (brand-keyword lists, generic obfuscation patterns, lookalike templates) remain in the ruleset as **non-dispositive**: they MAY contribute evidence to the weighted-average rule rows but MUST NOT short-circuit `ruleScore` to `1.0`. This keeps detection breadth without letting low-precision heuristics reach the auto-block path.
3. **Appeal and rollback path.** An auto-block produced by this override MUST remain analyst-reversible. A security-team review (`MODIFY` with an explicit `finalVerdict`) corrects `user_report.verdict` and the derived `scanned_url.community_verdict` through the normal review write path — per the **C4 verdict-table distinction**, the correction is written to the final-verdict tables only, never to `secbret_analysis.verdict`. When a false positive is confirmed, the offending marker MUST be demoted (its `dispositiveEligible` flag cleared) or removed in the next ruleset version, and prior auto-blocks attributable to that marker + ruleset version (locatable via the recorded `kitRulesetVersion`) SHOULD be re-queued for human review.
4. **Precision monitoring.** Auto-block decisions driven by the dispositive override MUST be included in the auto-decision sampling/audit loop defined for score calibration (see the **Calibration & correlation caveat (B5)** below — the same harness, not a duplicate): a configurable fraction of dispositive auto-blocks is routed to human audit, and dispositive-marker precision is reported per ruleset version. Any marker whose measured precision falls below the dispositive bar MUST lose its `dispositiveEligible` flag until re-qualified.

### Scan Result Overall Score

`scan_result.overall_score` is the **scanner's own composite metric**, computed synchronously on completion of the Tier 1–3 scan (before the AI engine runs). It is **not** the same as `secbret_analysis.threat_score`.

**Computation:**

```
overall_score = mean(max_score(T) for T in [Tier1, Tier2, Tier3] if T is not empty)
```

where `max_score(TierN)` is the highest severity value found in that tier, normalized to `[0.00, 1.00]`.

**Canonical rules (single source of truth):**
- A tier with **no findings** is **excluded** from the mean (not treated as 0.0).
- If **all tiers** produce empty findings (impossible for Tier 1, but possible when scan data is missing), `overall_score` is `NULL`.
- `NULL` means "not enough data to score" and is distinct from `0.0` (which would mean "scanned and found fully clean").

The AI's `threat_score` supersedes this heuristic for incident reporting and public dashboard display.

### Synchronous-Ceiling ML Fallback

When the rule score falls in the uncertain zone, the ML sidecar is consulted **synchronously** with a hard ceiling to prevent cascading latency.

```
if 0.05 < ruleScore < 0.95:
    call ML sidecar with 2-second timeout (synchronous ceiling)
    if timeout or circuit breaker OPEN:
        combinedScore = ruleScore          (rules-only fallback)
    else:
        combinedScore = (ruleScore × 0.4) + (mlScore × 0.6)
else:
    combinedScore = ruleScore
```

> **Fail-safe posture on ML outage (B4).** When the ML sidecar times out or the
> circuit breaker is OPEN, the fallback is rules-only. Because the non-dispositive
> weighted-average `ruleScore` never exceeds `0.827` (< 0.95), an uncertain scan
> that ML would otherwise have pushed over the auto-block line instead degrades to
> `PENDING_REVIEW` — a human analyst, never a silent auto-benign. This is
> intentional under-blocking: an ML outage moves borderline cases **toward** human
> review, never toward an incorrect automated disposition. The **dispositive
> override still fires** during an outage (a known-phishing-kit hit yields
> `ruleScore = 1.0 → combinedScore = 1.0 → VERIFIED_MALICIOUS`), so near-certain
> malicious evidence is still auto-blocked without the ML sidecar.

#### Auto-Action Thresholds

Once the `combinedScore` is computed (from rules alone or rules + ML), the system applies auto-action thresholds to determine whether a report is resolved automatically or queued for human review:

```
combinedScore >= 0.95  → VERIFIED_MALICIOUS (auto-approved)
combinedScore <= 0.05  → VERIFIED_BENIGN    (auto-rejected)
0.05 < combinedScore < 0.95  → PENDING_REVIEW (human analyst)
```

**Tentative-verdict derivation (normative).** Independently of the auto-action outcome above, every analysis row MUST also record the AI's tentative verdict in `secbret_analysis.verdict` (NOT NULL, constrained to `BENIGN`/`SUSPICIOUS` by `chk_analysis_verdict`). The mapping is:

```
combinedScore <= 0.05  → secbret_analysis.verdict = BENIGN
combinedScore >  0.05  → secbret_analysis.verdict = SUSPICIOUS
```

This applies uniformly to all three auto-action outcomes — including the dispositive-override path (`combinedScore = 1.0` writes `SUSPICIOUS`). The tentative verdict never carries `VERIFIED_*` values; the final disposition is written only to `user_report.verdict` / `security_team_review.final_verdict` (see the C4 verdict-table distinction in Part III §9).

The ML consultation zone `[0.05, 0.95]` is aligned with the auto-action threshold boundaries. A `ruleScore` ≤ 0.05 or ≥ 0.95 is already extreme enough that ML cannot change the final disposition; for all other scores, ML input can swing the combined score above or below the auto-action thresholds. The interval is open `(0.05, 0.95)` because the boundary values already fix the outcome regardless of ML.

> **Calibration & correlation caveat (B5).** The weighted sum treats the eight
> indicators as independent, but several are correlated in practice — homoglyph
> domains, external form actions, and hidden iframes frequently co-occur within a
> single phishing kit — so an additive model can double-count one underlying cause.
> The weights and the `0.05 / 0.95` boundaries are heuristic **defaults**, not
> validated coefficients. Before production they MUST be calibrated against a
> labeled dataset, reporting precision and recall at each auto-action boundary; the
> boundaries are config-tunable (`autoApproveHigh` / `autoApproveLow`) so
> recalibration needs no redeploy. Until calibrated, prefer a wider
> `PENDING_REVIEW` band (raise `autoApproveHigh`, lower `autoApproveLow`) to bias
> toward human review.

### ML Sidecar (Python, gRPC)

| Aspect | Detail |
|--------|--------|
| **Model** | Pre-trained scikit-learn/XGBoost classifier for phishing detection |
| **Input** | Feature vector: domain age, SSL, form count, URL entropy, homoglyphs, brand keywords |
| **Output** | Score (0.0-1.0), confidence |
| **Protocol** | gRPC with Protocol Buffers |
| **Timeout** | 2 seconds. On timeout, use ruleScore only. |

### Circuit Breaker (ML Sidecar)

To prevent 2-second timeout waits on every uncertain scan when the ML sidecar is degraded, a circuit breaker guards all gRPC calls.

| Parameter | Value |
|-----------|-------|
| **Failure threshold** | 5 errors in 60 seconds |
| **Open state duration** | 30 seconds |
| **Half-open probe count** | **Exactly 1 request** |
| **On open** | Skip ML, use ruleScore only |

> **Implementation Note:** The gRPC `ManagedChannel` must be a CDI `@ApplicationScoped` singleton, injected into the ML client, with shutdown registered via `@PreDestroy`. The circuit breaker state is held on the same singleton. Creating a new channel per classification call would defeat the circuit breaker and add TLS handshake overhead.

**States:**
- **CLOSED**: Normal operation; calls pass through to ML sidecar
- **OPEN**: After 5 failures in 60s; all calls skip ML, use ruleScore only
- **HALF-OPEN**: After 30s cooldown; **next single call is a probe**. If it succeeds → CLOSED (reset failure count). If it fails → OPEN (restart 30s timer).

> **Atomic probe admission (B6).** "Exactly one probe" MUST be enforced with an
> atomic compare-and-set, not a read-then-write. Under concurrent uncertain scans,
> the OPEN→HALF-OPEN transition can be observed by many threads simultaneously; a
> naïve `if state == HALF_OPEN { send probe }` lets N threads all fire probes and
> defeats the breaker. Implement the state as a single `AtomicReference` (or an
> `AtomicInteger` token) and admit the probe only to the one thread that wins
> `compareAndSet(HALF_OPEN, HALF_OPEN_PROBING)`; all other threads take the
> rules-only fallback until the probe resolves the state. Required concurrency test:
> spawn ≥ 50 threads against a HALF-OPEN breaker and assert exactly one reaches the
> sidecar.

### ML Model Version Tracking

Every `ClassificationResponse` includes `model_version`. The application logs this at INFO level on every ML call and stores it in `secbret_analysis.model_version` (V18 migration). When the ML sidecar is not consulted (rules-only path, `ml_consulted = false`), `model_version` is **NULL** — there is no version string for the rules engine itself; the kit-ruleset version is tracked separately as `tier3_findings.kitRulesetVersion`. On version change, log WARN so operators can correlate score shifts with model rollouts. No automatic rejection of results; the operator controls model deployment via sidecar container swap.

### gRPC Contract (protosec.proto)

```protobuf
syntax = "proto3";

package secbret.ml;

service MLScorer {
    rpc Classify (ClassificationRequest) returns (ClassificationResponse);
}

message ClassificationRequest {
    string url = 1;
    double rule_score = 2;
    string tier1_findings_json = 3;
    string tier2_findings_json = 4;
    string tier3_findings_json = 5;
}

message ClassificationResponse {
    double ml_score = 1;
    double confidence = 2;
    string model_version = 3;
}
```

---

## 8. PDF Report Layout (3-Page Condensed)

### Page 1: Score & Verdict
- SecBret logo + title
- Target URL + scan date
- **Large threat score** (0.0-1.0) with color-coded gauge (green/yellow/red)
- **Verdict badge** (BENIGN / SUSPICIOUS / VERIFIED_MALICIOUS / VERIFIED_BENIGN)
- Summary paragraph (auto-generated from reasoning chain)

### Page 2: Executive Summary & AI Reasoning
- SecBret reasoning chain (numbered list of factors)
- ML model contribution (if consulted)
- Security Team review notes (if reviewed by human)
- Final community verdict for the URL

### Page 3: Technical Findings
- **Tier 1:** Domain age, SSL details, HTTP headers, DNS, WHOIS
- **Tier 2:** Forms, scripts, external domains, content size
- **Tier 3:** Phishing kit match, CVEs, outdated libraries, open redirects
- Footer: Report ID, generation timestamp, share link UUID

> **Note on missing SecBretAnalysis:** When a PDF is generated for a URL with scan results but no incident report (therefore no SecBretAnalysis), Page 2 renders placeholder text: 'No AI analysis has been run for this URL. The findings below are based on automated scan results only.' The "ML model contribution" and "Security Team review notes" sections are omitted.
>
> **Page 1 score fallback:** When no `SecBretAnalysis` exists, Page 1 displays `scan_result.overall_score` (the aggregated tier scan score) in place of `threat_score`, and labels the gauge **"Scan Score"** rather than "Threat Score" to avoid implying AI analysis occurred. If `overall_score` is also `NULL` (scan tiers returned no data), the gauge is replaced with the text **"N/A — insufficient scan data"** and the verdict badge is omitted.
>
> **APPROVE Threshold Note:** When an analyst uses `APPROVE`, the final verdict is derived from `secbret_analysis.threat_score`: score >= 0.50 → VERIFIED_MALICIOUS, score < 0.50 → VERIFIED_BENIGN. The 0.50 threshold is the default value specified by the `AUTO_APPROVE_ANALYST_THRESHOLD` environment variable. Analysts who agree with a borderline AI assessment should use `MODIFY` with an explicit `finalVerdict` instead.

---

## 8.5. Supplementary Design Clarifications

### GDPR-Deleted User Display in API Responses

When a user account is hard-deleted (`DELETE /auth/me`), FK columns such as `reported_by`, `reviewed_by`, and `created_by` are set to NULL by the database cascade. API responses that include username strings (`reportedBy`, `reviewedBy`) must handle this null gracefully:

| Field | Null behavior |
|-------|--------------|
| `reportedBy` (string) | Render as `"[deleted]"` |
| `reviewedBy` (string) | Render as `"[deleted]"` |
| `reportedBy.id` (UUID object in admin review detail) | Omit the `id` field; include only `username: "[deleted]"` |

> DTOs must declare `reviewedBy` / `reportedBy` as `@Nullable String` and map
> the entity's nullable FK to `"[deleted]"` when null. Never throw a NPE or return
> a raw null in the JSON body.

> **C3 — GDPR Deletion Transaction Ordering (DDL-enforced via V20 trigger):**
>
> The `audit_log` table uses `ON DELETE SET NULL` on `actor_id`. Without protection,
> a hard `DELETE FROM secbret_user` would nullify `audit_log.actor_id` before the
> tombstone UPDATE can fire — silently losing the `deleted_{uuid}` username marker.
>
> **As of V20, this is enforced at the DDL level** by the `tombstone_audit_before_delete`
> BEFORE DELETE trigger on `secbret_user`. The trigger fires before the DELETE and before
> the `ON DELETE SET NULL` cascade, writing the tombstone while `actor_id` is still set.
> This applies unconditionally to all deletion paths: `UserService.deleteAccount()`,
> future admin bulk-delete jobs, and manual SQL.
>
> `UserService.deleteAccount()` **must remove** its explicit tombstone UPDATE — the
> trigger is the single source of truth. Retaining a duplicate UPDATE creates misleading
> redundancy and makes it harder to audit where tombstoning actually happens. The correct
> application-level sequence is:
>
> 1. `DELETE FROM secbret_user WHERE id = :userId`
>    (the BEFORE DELETE trigger fires automatically and writes the tombstone first)
>
> Any new deletion path that bypasses the `secbret_user` DELETE (e.g. direct `audit_log`
> row deletion) must tombstone `actor_username` manually — the trigger only activates on
> `secbret_user` deletes.

---

### Community Verdict Values

The `scanned_url.community_verdict` column stores one of four values (or NULL):

| Value | Set when |
|-------|----------|
| `MALICIOUS` | A report is resolved as VERIFIED_MALICIOUS (by auto-approval or human review) |
| `BENIGN` | A report is resolved as VERIFIED_BENIGN (by auto-rejection or human review) |
| `SUSPICIOUS` | Reserved for future use (e.g. concurrent unresolved reports); not written in v1 |
| `UNKNOWN` | URL has been seen but no verdict has been established; written at URL creation time |
| `NULL` | No community verdict record exists yet for this URL |

The `VERIFIED_*` prefixed values are NOT used for `community_verdict`; they live exclusively on `user_report.verdict` and `security_team_review.final_verdict` (never on `secbret_analysis.verdict`, which is constrained to `BENIGN`/`SUSPICIOUS` — see the C4 verdict-table distinction below). The database CHECK constraint permits all four non-null values; the OpenAPI `CommunityVerdict` enum exposes all four so API consumers can handle every possible response without serialization errors.

> **C4 — Verdict Table Distinction (read before implementing any verdict-writing code):**
>
> There are two completely separate verdict domains in this system. Writing to the wrong
> table will NOT always be caught at the database level and will silently corrupt
> downstream logic:
>
> | Domain | Table column | Allowed values | Written by |
> |--------|-------------|----------------|------------|
> | AI tentative | `secbret_analysis.verdict` | `BENIGN`, `SUSPICIOUS` | Rules engine + ML sidecar only |
> | Final resolved | `user_report.verdict` | `VERIFIED_MALICIOUS`, `VERIFIED_BENIGN`, `REJECTED` | Auto-resolution or human review |
> | Final resolved | `security_team_review.final_verdict` | `VERIFIED_MALICIOUS`, `VERIFIED_BENIGN`, `REJECTED` | Human analyst only |
>
> `chk_analysis_verdict` will reject `VERIFIED_*` values at the DB level.
> `chk_report_verdict` now carries a **dual-layer guard (C1 FIX — V17)**: it allows
> `NULL` and the three `VERIFIED_*`/`REJECTED` values AND explicitly rejects `BENIGN`
> and `SUSPICIOUS` via a `NOT IN` clause. An accidental write of an AI-only value to
> `user_report.verdict` is therefore caught at the DB level. As a second layer,
> `IncidentPersistence` must carry a runtime assertion (e.g. Java `assert` or
> a precondition check) that verifies the value it is about to write is never
> `BENIGN` or `SUSPICIOUS` before issuing the UPDATE. Application-level discipline
> remains the primary guard; the DB constraint is the backstop.

### security_team_review Timestamps

`created_at` and `reviewed_at` are both set at the moment the `POST /admin/reviews/{reportId}` request is processed in v1 (no draft state). They are semantically distinct:

- `created_at` — when the review record row was inserted
- `reviewed_at` — when the analyst submitted their final decision

In v1 these are set in the same DB transaction and will be identical within milliseconds. The distinction matters in v2 if draft reviews are introduced (where `created_at` ≠ `reviewed_at`).

---

### REJECT Action Behavior

When a report is `REJECTED`, `user_report.status` becomes `REJECTED` and `user_report.verdict` becomes `REJECTED`. `scanned_url.community_verdict` is **not modified** by the REJECT action. If the URL had a prior community verdict (from an earlier verified report), that verdict remains. REJECT means "this specific report is invalid," not "this URL is benign."

### NULL Tier Response Behavior (QUICK Scans)

When a QUICK scan runs only Tier 1, the API returns empty objects for unused tiers:
```json
{
  "tier1Findings": { "...full data..." },
  "tier2Findings": {},
  "tier3Findings": {}
}
```
Clients always receive the same JSON shape regardless of scan depth.

---

## 9. Error Handling Strategy

| Layer | Strategy |
|-------|----------|
| **Controller** | Bean Validation on DTOs → 400 with field-level errors |
| **Service** | Custom exceptions: `ScanFailedException`, `ResourceNotFoundException`, `AuthorizationException` |
| **Repository** | JPA `EntityNotFoundException` → mapped to 404; `ConstraintViolationException` → mapped to 409 |
| **Scanner** | `IOException` / `TimeoutException` → mark ScanJob as FAILED with error_message |
| **ML Sidecar** | gRPC `StatusRuntimeException` → use ruleScore only; log warning |
| **PDF Generation** | `DocumentException` / `IOException` → mark ReportJob as FAILED with error_message |
| **Email (SMTP)** | `MessagingException` on send → log ERROR, return 202 anyway (anti-enumeration); token remains valid for retry. Never rollback the `password_reset_token` row on send failure. |
| **Global** | `@Provider` JAX-RS `ExceptionMapper<Throwable>` → catch-all 500 with structured JSON |
| **MVC** | Krazo `@Controller` methods return error views with model attributes |

### Custom Exception Hierarchy

```
SecBretException (base)
├── ResourceNotFoundException → 404
├── ValidationException → 400
├── AuthorizationException → 403
├── AuthenticationException → 401
├── ConflictException → 409
├── ScanFailedException → maps to ScanJob.status=FAILED
├── ReportGenerationException → maps to ReportJob.status=FAILED
└── MLSidecarUnavailableException → graceful fallback to rules only
```

---

## 9.5. Request Tracing and Correlation IDs

At 10–100 scans/day the log volume is low, but debugging a single failed scan across the scanner → ML sidecar → report generator pipeline requires correlating log lines. Without a shared identifier, grepping across logs by timestamp is imprecise and brittle.

### `X-Correlation-Id` Header

1. **Generation** — On every incoming HTTP request, the first servlet filter (before rate limiting) generates a new `UUID` if the client does not supply `X-Correlation-Id`.
2. **Propagation** — The correlation ID is stored in a `ThreadLocal<UUID>` via a `CorrelationContext` CDI `@RequestScoped` bean.
3. **Downstream** — Every outgoing call (gRPC to ML sidecar, SMTP email dispatch, HIBP API check) includes the correlation ID in an `X-Correlation-Id` header or metadata key.
4. **Logging** — The SLF4J `logback.xml` layout includes `%X{correlationId}` so every log line is tagged automatically:
   ```json
   {"timestamp":"2026","level":"INFO","correlationId":"a1b2...","message":"Scan completed"}
   ```
5. **Error Responses** — Every structured JSON error response includes a `correlationId` field so support staff can cross-reference with traces.

| Layer | Mechanism |
|-------|-----------|
| HTTP requests | `X-Correlation-Id` request header |
| Thread-local | `CorrelationContext` (CDI `@RequestScoped`) |
| gRPC metadata | `X-Correlation-Id` key in `Metadata` |
| gRPC response | `X-Correlation-Id` in response `Metadata` |
| SMTP | X-Mailer-Correlation-Id header (optional, for traceability) |
| SLF4J/Logback | MDC key `correlationId` |
| Error responses | `correlationId` JSON field |

### Implementation

```java
@ApplicationScoped
public class CorrelationIdFilter implements Filter {

    @Inject
    private CorrelationContext correlationContext;

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpReq = (HttpServletRequest) req;
        String header = httpReq.getHeader("X-Correlation-Id");
        UUID correlationId = header != null ? UUID.fromString(header) : UUID.randomUUID();
        correlationContext.set(correlationId);
        MDC.put("correlationId", correlationId.toString());
        try {
            chain.doFilter(req, res);
        } finally {
            MDC.remove("correlationId");
        }
    }
}
```

### Response Header
Every API response includes the correlation ID that was used for that request:

```
X-Correlation-Id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

---

## 10. Outage Behavior

### PostgreSQL Unavailable

| Scenario | Behavior |
|----------|----------|
| **Startup** | Payara fails to start; logs error, exits |
| **Runtime** | All data-dependent requests return `503 Service Unavailable`; health check fails |
| **Recovery** | Automatic once PostgreSQL reconnects |

### Payara (Application Server) Unavailable

| Scenario | Behavior |
|----------|----------|
| **Complete outage** | Connection refused; client retries or fails fast |
| **Partial (OOM)** | JVM crashes; Docker Compose auto-restarts container |
| **Health check** | `GET /api/v1/health/ready` returns `200 OK` when healthy, `503` otherwise |

### ML Sidecar Unavailable

| Scenario | Behavior |
|----------|----------|
| **Startup** | Payara starts; ML client initialized lazily on first uncertain scan |
| **Runtime** | Circuit breaker opens after 5 failures; falls back to ruleScore |
| **Recovery** | Circuit breaker transitions to HALF-OPEN after 30s; auto-recovers |

---

## 10.4 Stale Job Recovery

SecBret explicitly excludes scheduled cron tasks, but the application must handle the case where the JVM or host crashes while `scan_job` or `report_job` rows are in non-terminal states. A CDI `@Observes @Initialized(ApplicationScoped.class)` startup bean runs on every Payara start and marks all interrupted jobs as `FAILED`:

```sql
UPDATE scan_job
SET status = 'FAILED',
    error_message = COALESCE(error_message, '') || '; server restart'
WHERE status IN ('PENDING', 'RUNNING');

UPDATE report_job
SET status = 'FAILED',
    error_message = COALESCE(error_message, '') || '; server restart'
WHERE status IN ('PENDING', 'GENERATING');
```

> **Caution:** In a multi-instance deployment (not planned for v1), a coordination lock would be required. For the single-instance Payara deployment, the application startup hook is sufficient.

---

## 10.5 Resilience: Read-Through Caching (v2)

The architecture currently has no degraded mode when PostgreSQL is unavailable (all requests return 503). At 10–100 scans/day, full database outage is acceptable (≈4 hours RTO), but a **read-only degraded mode** for public-facing queries would keep the public dashboard readable during brief DB maintenance or networking hiccups.

### Strategy
Implement a **read-through cache** using a `ConcurrentHashMap`-backed in-memory store with TTL-based eviction. This provides instant access to frequently accessed, low-mutability data even when the database is temporarily unreachable.

### Cached Data

| Data | TTL | Rationale |
|------|-----|-----------|
| `GET /dashboard/public` results | 5 minutes | Public dashboard changes infrequently; stale data acceptable |
| URL latest scan result (`GET /api/v1/scan/url/{urlId}`) | 10 minutes | Scan results are immutable once COMPLETED |
| Report job status | 1 minute | Short-term; updated frequently during generation |
| User roles / enabled status | 15 minutes | Role changes are rare; stale reads acceptable |

### Cache Invalidation

- **On write** — `ScannedUrlRepository`, `ScanResultRepository`, `ReportJobRepository`, and `UserRepository` publish CDI events (`CacheInvalidationEvent`) after successful `INSERT`/`UPDATE`.
- **On receive** — `CacheInvalidationEvent` listeners remove the corresponding key from the cache (no-op if the key was not cached).
- **TTL expiry** — Keys automatically expire after TTL; the next read misses cache, fetches from DB, and warms the cache.

### Degraded Mode Behavior

| Scenario | Normal | Degraded |
|----------|--------|----------|
| `GET /dashboard/public` | Cache → DB → cache miss updates cache | Cache → cache miss → return empty list or 503 |
| `GET /api/v1/scan/url/{urlId}` | Cache → DB → cache miss updates cache | Cache → cache miss → return 503 |
| `GET /api/v1/dashboard/public?url={url}` | Cache → DB → cache miss updates cache | Cache → cache miss → return 404 |

### v2 Path
Replace the `ConcurrentHashMap` with a dedicated caching layer (e.g., Caffeine, Redis, or a separate Memcached container) to support multi-instance deployments and larger cache sizes. The read-through API (`CacheService.get(key, supplier)`) should be designed as an interface today so the implementation can be swapped out in v2 without changing controller or service logic.

---

## 10.6 Audit Log Integration

The `AuditLogService` is invoked synchronously (within the same `@Transactional` boundary) by the following services before completing the primary operation:

| Service | Method | Action | Logged Fields |
|---------|--------|--------|---------------|
| `SecurityTeamReviewService` | `submit()` | REVIEW_APPROVED / REJECTED / MODIFIED | reportId, reviewerId, action, finalVerdict |
| `UserService` | `changeRole()` | ROLE_CHANGED | targetUserId, oldRole, newRole |
| `UserService` | `changeStatus()` | USER_ENABLED / DISABLED | targetUserId, enabled state |
| `UserService` | `deleteAccount()` | ACCOUNT_DELETED | userId (before deletion) |

Implementation: `AuditLogService.log(AuditAction action, UUID actorId, UUID targetId, String targetType, Map<String,Object> detail)` is called as the last step inside the `@Transactional` boundary. If the audit insert fails, the entire transaction rolls back.

**Note:** Scan submissions, report submissions, and share link creations are NOT audited to avoid log volume at 10-100 ops/day. These may be added in v2.

---

## 11. Deferred to v2

The following features were considered for the initial release but **deferred to v2** due to current low scale (10–100 scans/day). They have been removed from the v1 OpenAPI specification entirely — no stub endpoints.

| Feature | Rationale |
|---------|-----------|
| **Batch scan** (`POST /scan/batch`) | Low volume; single scan per request sufficient |
| **Webhooks** (`/webhooks/*`) | No external integrations needed at this scale |
| **API tokens** (`/auth/tokens/*`) | Session auth sufficient for web UI |

> These endpoints will be added back in the v2 OpenAPI specification.

---

## 12. Project Structure (Final)

```
SecBret/
├── pom.xml
├── docker-compose.yml
├── Dockerfile
├── .env.example
├── docs/
│   └── architecture/decisions/
│       ├── 0001-use-hybrid-ai-engine.md
│       ├── 0002-store-pdfs-in-database.md
│       ├── 0003-single-maven-module.md
│       ├── 0004-use-jsp-htmx-frontend.md
│       ├── 0005-in-process-job-queue.md
│       ├── 0006-docker-compose-deployment.md
│       └── 0007-postgres-14-baseline.md
├── spec/
│   ├── README.md                 (this index)
│   ├── Part II            (this document)
│   ├── architecture.puml
│   ├── data-model.puml
│   ├── workflows.puml
│   ├── Part III
│   └── Part IV
├── src/
│   ├── main/
│   │   ├── java/com/secbret/
│   │   │   ├── config/           (CDI producers, Payara config)
│   │   │   ├── controller/       (MVC controllers: web + REST)
│   │   │   ├── service/          (CDI service beans)
│   │   │   ├── email/            (Jakarta Mail templates; EmailService is in service/)
│   │   │   ├── scanner/          (Tier 1, 2, 3 engines)
│   │   │   ├── ai/               (SecBret rules + gRPC client)
│   │   │   ├── model/
│   │   │   │   ├── entity/       (JPA entities)
│   │   │   │   ├── dto/          (Request/Response DTOs)
│   │   │   │   └── enums/       (All enumerations)
│   │   │   ├── repository/       (JPA repository interfaces)
│   │   │   ├── security/         (Soteria, IdentityStore)
│   │   │   ├── report/           (OpenPDF generation)
│   │   │   └── filter/           (Rate limit, security headers, CORS, correlation ID)
│   │   ├── resources/
│   │   │   ├── META-INF/
│   │   │   │   └── persistence.xml
│   │   │   ├── logback.xml
│   │   │   └── db/migration/     (Flyway V1-V20 SQL scripts)
│   │   └── webapp/
│   │       ├── WEB-INF/
│   │       │   ├── beans.xml
│   │       │   ├── web.xml
│   │       │   └── views/        (JSP templates listed above)
│   │       └── static/
│   │           ├── css/          (custom styles)
│   │           └── js/           (custom HTMX helpers)
│   └── test/
│       ├── java/com/secbret/
│       │   ├── service/          (Service unit tests)
│       │   ├── scanner/          (Scanner unit tests)
│       │   ├── controller/       (Controller unit tests)
│       │   └── integration/      (Testcontainers integration tests)
│       └── resources/
│           └── logback-test.xml
├── ml-sidecar/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── server.py                (gRPC server)
│   ├── model/
│   │   ├── classifier.pkl       (pre-trained model)
│   │   └── feature_extractor.py
│   └── proto/
│       └── secbret.proto
```

---

## 13. User Stories

| ID | Role | Goal | Benefit |
|----|------|------|---------|
| US-01 | REPORTER | Submit a URL for automated scanning | Quickly assess if a URL is malicious without manual investigation |
| US-02 | REPORTER | View scan results with detailed findings | Understand exactly what indicators were found (Tier 1-3) |
| US-03 | REPORTER | Report a phishing URL with evidence | Alert the security community and trigger AI analysis |
| US-04 | REPORTER | Generate a PDF report of scan findings | Share a portable, formatted risk summary with non-technical stakeholders |
| US-05 | REPORTER | Create a share link for a report | Distribute findings via a simple URL that expires after a configurable period |
| US-06 | ANALYST | Review pending incident reports in a queue | Triage incoming threats efficiently without missing items |
| US-07 | ANALYST | Approve or reject incident reports with notes | Provide human verification that complements the AI analysis |
| US-08 | ADMIN | Manage user roles and enabled status | Control who has access to sensitive review and admin functions |
| US-09 | ANYONE | View the public dashboard of verified URLs | Check whether a known URL has been verified as malicious or benign by the community |
| US-10 | REPORTER | Register an account and authenticate | Securely access personal scan history and reports |

---

## 14. Non-Functional Requirements

These are engineering targets, not contractual SLAs. They exist to size the system honestly and to avoid building for a scale we don't have. The single recurring assumption behind almost every number below is the scale line: **10–100 scans/day.**

| Attribute | Target | Rationale |
|-----------|--------|-----------|
| **Scale (peak)** | ~10-100 scans/day, ~5 API req/s | Single-instance Payara; in-process queue sufficient |
| **Availability** | 99.5% uptime (~44 min/month downtime) | Acceptable for a non-critical internal tool; single-instance deployment |
| **Latency (classification)** | P95 < 2s for synchronized verdict (rules + optional ML) | When uncertain zone is hit (0.05–0.95), gRPC ML call adds up to 2s; rules-only path is <200ms |
| **Latency (Scan)** | P95 < 30s for DEEP scan, P95 < 10s for QUICK | Async operation; user polls via HTMX every 3s |
| **Data volume (3 years)** | ~1.5 GB (scans + reports + PDFs) | ~25 MB/month PDFs from BLOB storage; ~500 MB metadata |
| **Consistency** | Strong (single PostgreSQL instance, ACID) | All operations read their writes; no eventual-consistency tolerance |
| **Security** | No PII/PCI/HIPAA scope; passwords hashed with BCrypt cost 12 | Application handles URLs and user emails only (email is PII-adjacent; GDPR applies) |
| **Compliance** | GDPR right-to-be-forgotten (hard DELETE on `secbret_user`, `ON DELETE SET NULL` for user FKs, `audit_log.actor_username` retains `deleted_{uuid}` tombstone) | Users may request account deletion; `secbret_user` row is hard-deleted so DB cascade constraints fire; dependent user FKs are set to NULL so scan/report data survives with anonymized references; `audit_log.actor_username` preserves the `deleted_{uuid}` tombstone for audit history; `api_token`, `password_reset_token`, `idempotency_key`, `webhook_subscription` are CASCADE DELETED |
| **Backup RPO** | 24 hours | Daily pg_dump piped to host-mounted directory outside the Docker volume |
| **Backup RTO** | 4 hours | Restore from last pg_dump backup (daily). WAL archiving is not configured in v1. |

---

## 15. Failure Mode Analysis

### Component Failure Table

| Component | Failure Mode | Blast Radius | Degraded Behavior | Recovery |
|-----------|-------------|--------------|-------------------|----------|
| **PostgreSQL** | Database unreachable, connection pool exhausted | **Total system outage**: all API endpoints fail, UI shows errors | No degraded mode — application returns 503 "Service Unavailable" with JSON body. Static fallback page from servlet container. | Restart Postgres container; application auto-reconnects via HikariCP pool. If data corruption: restore from pg_dump backup. |
| **Payara Server** | JVM OOM, thread pool exhaustion, crash | **Total system outage**: all endpoints fail | None at application level. Docker Compose `restart: unless-stopped` restarts container. | Container restart. Check OOM logs. Tune `-Xmx` if needed. |
| **ML Sidecar** | gRPC unavailable, slow response, model error | Partial: uncertain-score analysis falls back to rules only | Circuit breaker: **5 errors/60s → OPEN → 30s cooldown → HALF-OPEN with exactly 1 probe**. On OPEN: rules-only fallback. | Restart sidecar container. Auto-recovery via single-probe half-open. |
| **Target URL (scanned site)** | Unreachable, timeout, DNS failure | Isolated to single scan job | Mark ScanJob as FAILED with `errorMessage`. No retry. User resubmits. | User action: resubmit scan when target is available. |
| **HIBP API** | Timeout, rate-limit, unreachable | Isolated to registration endpoint | Fail-open: skip HIBP check, allow registration. Log warning. | Next registration attempt retries HIBP check. |
| **SMTP Server** | Unreachable, auth failure, timeout | Isolated to password-reset flow | Fail-silent: return 202 (anti-enumeration), log ERROR. Token remains valid; user can request again. | Fix SMTP credentials / connectivity; no application restart needed. |
| **Disk full (pg_data volume)** | PostgreSQL stops, inserts fail | **Total system outage**: all write operations fail | Reads may still succeed briefly. Degraded read-only mode not implemented — treat as total outage. | Free disk space or increase volume size. Restart Postgres. |

### Resilience Patterns Applied

| Pattern | Implementation | Scope |
|---------|---------------|-------|
| **Timeouts** | HTTP: 5s connect + 5s read (scanner). gRPC: 2s (ML sidecar). JDBC: 30s (connection pool). | All external calls |
| **Retries** | None for scans (mark FAILED). HIBP: single attempt, fail-open. | Intentional: avoid retry loops on dead URLs |
| **Circuit Breaker** | ML gRPC client: trip after 5 errors in 60s → OPEN → 30s cooldown → HALF-OPEN with exactly 1 probe. State tracked per instance in memory. | ML sidecar only |
| **Bulkheads** | Managed executor thread pools separated by domain: scan pool, analysis pool, report pool. Each has independent queue. | Thread pool isolation via separate `@ManagedExecutorService` injections |
| **Fallbacks** | ML sidecar failure → `combinedScore = ruleScore`. HIBP failure → allow registration. | External dependency degradation |

### Circuit Breaker: ML Sidecar gRPC Client

```
State machine (per-instance, in-memory):
  CLOSED ──(5 errors in 60s)──> OPEN ──(30s timer)──> HALF_OPEN
                                                            │
                                                ┌───────────┘
                                                ▼
                                          probe (1 request)
                                                │
                                    ┌───────────┴───────────┐
                                    ▼                       ▼
                              success                       failure
                                  │                           │
                             CLOSED                      OPEN
                          (reset count)               (restart timer)

On HALF_OPEN: allow exactly 1 probe request. If it succeeds → CLOSED.
If it fails → OPEN with full 30s cooldown.
```

#### v2 Migration: Circuit Breaker State

The in-memory circuit breaker is correct for the single-instance v1 deployment. Before provisioning a second Payara instance, the circuit breaker state must move to a shared store so that all instances observe the same OPEN/HALF-OPEN/CLOSED state. Candidate approaches: PostgreSQL advisory lock, Redis, or a dedicated state file managed by the ML sidecar. This must be resolved before any horizontal scaling.

---

## 15.5 Session Invalidation Mechanism

`DELETE /auth/me` (GDPR erasure) and a completed password reset (`POST /reset-password`) both guarantee that **all active sessions for the affected user are invalidated** immediately. This is implemented as follows:

### Mechanism

Payara's Jakarta Security (Soteria) uses the built-in HTTP session store backed by the servlet container. Sessions are identified by `JSESSIONID` cookies. `invalidateAllSessions()` first invalidates the caller's own session, then delegates to `SessionTracker` to invalidate every other session belonging to the user.

```java
@Inject
private HttpServletRequest request;

private void invalidateAllSessions(UUID userId) {
    HttpSession currentSession = request.getSession(false);
    if (currentSession != null) {
        currentSession.invalidate();
    }
    SessionTracker.invalidateByUserId(userId);
}
```

`SessionTracker` is an `@ApplicationScoped` CDI bean that:
- Registers every new session on `SessionCreatedEvent` (via `HttpSessionListener`)
- Stores `Map<UUID, Set<String>> userSessions` — mapping `userId → Set<sessionId>`
- On `invalidateByUserId(userId)`: iterates the session IDs, retrieves each from `ServletContext.getSession(sessionId)`, and calls `.invalidate()` on those that still exist
- On `SessionDestroyedEvent`: removes the session from the map to avoid stale references

### Scope and Limitations

| Scenario | Behaviour |
|----------|-----------|
| Password changed — caller's own session | Invalidated in same request |
| Password changed — all other open sessions | Invalidated via `SessionTracker` |
| Account deleted — all sessions | Invalidated before `secbret_user` row is hard-deleted |
| Multi-instance deployment (not v1) | `SessionTracker` is JVM-local; a shared session store (Redis, PostgreSQL `http_session` table) would be required before horizontal scaling |

> **v1 constraint:** This mechanism is correct for the single-instance Payara deployment. It is listed in §18 Known Gaps as a pre-condition for horizontal scaling.

---

## 16. Soft-Delete Enforcement

> **C4 FIX — `@Where` removed from v1 entities.** The `deleted_at` columns and partial
> indexes are pre-positioned in the schema, but no v1 API endpoint writes `deleted_at`.
> `@Where(clause = "deleted_at IS NULL")` is intentionally omitted. Because nothing in
> v1 writes `deleted_at`, the annotation would be a no-op for operational code. The
> important consequence is: **partial indexes are performance guards only — they do not
> provide JPA-level filtering.** Without `@Where`, any row whose `deleted_at` is set (by
> a test fixture, migration rollback, or manual SQL prompt) will still appear in all JPA
> queries — **data leakage, not data loss**. This is the opposite of the risk that
> exists when `@Where` *is* present: with `@Where`, accidentally-tombstoned rows would
> be silently hidden from queries (invisible exclusion). Both risks are real; in v1 the
> leakage risk is accepted because no write path touches `deleted_at` and a silent
> exclusion bug during development would be harder to diagnose.
>
> **Resolution:** `@Where` is omitted from v1 entities. The v2 migration path is
> specified below. The partial indexes remain — they are inert cost-free placeholders
> that become load-bearing in v2.

### v1 Entity declarations (no `@Where`)

Both entities deliberately omit `@Where("deleted_at IS NULL")` in v1, per the rationale above:

```java
@Entity
@Table(name = "scanned_url")
public class ScannedUrl { ... }

@Entity
@Table(name = "user_report")
public class UserReport { ... }
```

### v2 migration path — `@FilterDef` / `@Filter` instead of `@Where`

When v2 introduces write paths for `deleted_at`, **do not add `@Where`**. Use a named Hibernate filter instead, which can be selectively disabled for admin views:

```java
@Entity
@Table(name = "scanned_url")
@FilterDef(name = "excludeDeleted", defaultCondition = "deleted_at IS NULL")
@Filter(name = "excludeDeleted")
public class ScannedUrl { ... }
```

Enable the filter via a Jakarta Servlet `Filter` (or JAX-RS `ContainerRequestFilter` / CDI `@Interceptor`) for all non-admin requests:

```java
entityManager.unwrap(Session.class).enableFilter("excludeDeleted");
```

Admin endpoints that need to see tombstoned rows simply do not enable the filter, or use `entityManager.createNativeQuery(...)` for full-table reads.

> **Why `@FilterDef`/`@Filter` over `@Where`?** `@Where` is always-on and cannot be
> disabled per-request — admin views cannot see soft-deleted rows without a native query.
> `@Filter` is opt-in per session, giving the same default protection while allowing
> explicit overrides. Both are superior to PostgreSQL RLS at this scale (RLS adds
> connection-user complexity and opaque query plan behaviour with JPA).

> **Rationale for v1 omission:** RLS is elegant but JPA/Hibernate support is painful
> at the ORM level. At 10–100 scans/day a filter clause is pragmatic and sufficient —
> but only when it is actually filtering something. A filter that silently hides
> accidentally-tombstoned rows during development is more dangerous than no filter.

---

## 16.5 SecBretAnalysis INSERT Failure Path

`SecurityTeamReview` has a NOT NULL foreign key `secbret_analysis_id`. If the async `INSERT INTO secbret_analysis` fails before any `SecurityTeamReview` is created, the system enters the following state:

| Symptom | Root cause |
|---------|------------|
| `user_report.status` remains `PENDING` indefinitely | The async analysis event completed with a DB write failure; no status update was applied |
| No `SecurityTeamReview` row exists | FK constraint on `secbret_analysis_id` prevents insertion |
| Report does not appear in analyst review queue | `GET /admin/reviews/pending` filters on `status = PENDING_REVIEW` |

### Failure Handling

1. **The `IncidentService` async analysis handler catches the `PersistenceException`** from the failed INSERT inside the async event handler.
2. It logs the failure at `ERROR` level with the `correlationId`, `userReportId`, and the exception.
3. It sets `user_report.status = FAILED` (a terminal state added for this error path) and records the error detail in a new `error_message` column on `user_report`. This prevents the report from appearing stuck in `PENDING`.
4. The user discovers the failure by polling `GET /api/v1/incident/{reportId}`, which returns `status: FAILED` with a human-readable `errorMessage`.
5. No automatic retry is performed. The user must re-submit the incident report to trigger a fresh analysis.

> **v2 improvement:** Add a dead-letter queue or bounded retry (max 3 attempts, exponential back-off) before moving to `FAILED`.

---

## 17. Open Question Resolutions

Resolved design questions:

| # | Question | Resolution |
|---|----------|------------|
| 1 | **Base DDL convention** | V1 base DDL is the authoritative initial schema. V10–V18 are incremental and must use `IF NOT EXISTS` / `IF EXISTS` guards where columns or constraints overlap with the base DDL. See `Part IV` for annotated V17. |
| 2 | **Auto-reject → community_verdict** | Score ≤ 0.05 **does** set `community_verdict = BENIGN`. The workflow diagram (workflows.puml) and design-spec §8.5 are the canonical sources; the oversight is corrected. |
| 3 | **Public dashboard lookup** | Uses `?url=` query parameter on `GET /dashboard/public`. No internal `urlId` required for anonymous lookup. The `/{urlId}` sub-path is removed from OpenAPI. |
| 4 | **GDPR-deleted user display** | Null FK columns (reporter, reviewer, creator) render as the string `"[deleted]"` in API responses. See §8.5 GDPR-Deleted User Display. |
| 5 | **overall_score = NULL vs 0.0** | `NULL` = insufficient data (all tiers empty). `0.0` is not used as a sentinel; it would only appear if all tier max-scores genuinely compute to zero. See §7 Scan Result Overall Score. |

---

## 18. Known Gaps (Tracked for v2)

| # | Gap | Notes |
|---|-----|-------|
| 13 | ADR files missing | ✓ RESOLVED (v1). ADR-0001 … ADR-0007 decisions are recorded: hybrid AI engine, PDFs-in-DB, single Maven module, JSP/HTMX frontend, in-process job queue, Docker-Compose deployment, Postgres 14 baseline. |
| 14 | `project.md` missing | ✓ RESOLVED — the intended content is covered by this specification; a separate `project.md` is not needed. `project.md` removed from the §12 project-structure tree; do not create it. |
| 12 | JSONB findings schema | OpenAPI uses `additionalProperties: true` for tier findings — zero schema contract. Canonical structure is defined in `Part IV`. Consider $ref to inline schemas in v2. |
| 15 | Per-JVM rate limiter state | `RateLimitFilter` stores all bucket state in a `ConcurrentHashMap` local to the JVM. In a multi-instance deployment every instance maintains an independent set of counters, so a user can exhaust N × the configured limit by round-robining across instances. Before horizontal scaling: replace with a shared atomic store (Redis INCR+EXPIRE, or a PostgreSQL `rate_limit_bucket` table with advisory locks). Eviction sweep (§5 Rate Limiting) mitigates memory growth within a single instance but does not address the distributed case. v2 resolution: shared Redis rate-limit layer. |
| 16 | Session invalidation — single-JVM only | `SessionTracker` (§15.5) is JVM-local. A second Payara instance has its own session map and cannot invalidate sessions created on the first instance. Before horizontal scaling: move to a shared session store (Redis, PostgreSQL-backed `http_session` table). v2 resolution: same Redis layer as the rate limiter. |
| 17 | Soft-delete `@Where` deferred to v2 | `scanned_url` and `user_report` carry `deleted_at` columns and partial indexes but no v1 write path touches them. `@Where(clause = "deleted_at IS NULL")` is omitted from v1 entities (see §16) to prevent silent row-exclusion in test fixtures and migration rollbacks. **Pre-condition for v2 soft-delete feature:** (a) add `@FilterDef` / `@Filter` annotations (not `@Where`) to `ScannedUrl` and `UserReport`; (b) enable the filter via a Jakarta Servlet `Filter` (or JAX-RS `ContainerRequestFilter` / CDI `@Interceptor`) for all non-admin request paths; (c) verify that admin endpoints that must see tombstoned rows explicitly bypass or do not enable the filter; (d) write an integration test that inserts a row, sets `deleted_at`, and asserts the entity is excluded from standard queries and visible in admin queries. |
| 18 | Dispositive auto-block audit sampling is **off by default** | `AUTO_DECISION_SAMPLE_RATE` defaults to `0.0` (§Environment Variables), so the B5 calibration loop that diverts a sample of auto-decided reports to human audit is inactive out of the box. Because auto-block (`combinedScore >= 0.95`) is only reachable via a `knownPhishingKit` **dispositive override** (B1/B2: the non-dispositive weighted average caps at 0.827), a single false marker match can auto-publish `VERIFIED_MALICIOUS` for an innocent site with **no** human in the loop and **no** sampled audit trail. **Operator action item (do this at deployment, not v2):** set `AUTO_DECISION_SAMPLE_RATE` to a small non-zero value (suggested `0.05`–`0.10`) so dispositive auto-blocks are sampled into the human audit queue, and pair it with the Phishing-Kit Marker Governance review cadence (§7). Leaving it at `0.0` is an accepted risk only for deployments that also disable dispositive auto-block. |


---

# Part III — REST API

**Base URL:** `/api/v1` **Content-Type:** `application/json` **Authentication:** Session cookie (Soteria) for web UI. Bearer token support is deferred to v2.

This part is the prose rendering of `spec/openapi.yaml`; when the two disagree, the YAML is authoritative (it's what codegen and the contract tests run against). Authorization semantics (401 vs 403 vs 404) follow Part II §A.2 everywhere and are not re-explained per endpoint.

---

## Table of Contents

0. [Health Check](#0-health-check)
1. [Authentication & User Management](#1-authentication--user-management)
2. [URL Scanning](#2-url-scanning)
3. [Incident Reporting](#3-incident-reporting)
4. [Report Generation](#4-report-generation)
5. [Share Links](#5-share-links)
6. [Admin / Security Team](#6-admin--security-team)
7. [Public Dashboard](#7-public-dashboard)
8. [Error Responses](#8-error-responses)
9. [Enumerations](#9-enumerations)
10. [Deferred to v2](#10-deferred-to-v2)
11. [Document Cross-Reference](#11-document-cross-reference)

---

## 0. Health Check

Three probes for orchestrators: liveness (process alive), readiness (DB reachable), and dependency health — keeping dependency checks off the liveness path. No authentication required on any health endpoint.

### GET /health/live
Liveness probe — confirms the process is alive. Does **not** check database or downstream dependencies. Intended for orchestrator liveness checks. The Docker Compose `healthcheck` for the `payara` container uses `/health/ready` (readiness), **not** this probe.

**Response 200:** Process is alive.
```json
{ "status": "UP", "version": "1.0.0" }
```
**Response 503:** Process is unhealthy (JVM crash recovery).

---

### GET /health/ready
Readiness probe — confirms the application can serve traffic. Checks database connectivity. Returns 503 until the JDBC pool can reach PostgreSQL.

**Response 200 (ready):**
```json
{
  "status": "UP",
  "checks": { "database": "UP" },
  "version": "1.0.0"
}
```
**Response 503 (not ready — database unreachable):**
```json
{
  "status": "DOWN",
  "checks": { "database": "DOWN" },
  "version": "1.0.0"
}
```

---

### GET /health/dependencies
Dependency health — checks ML sidecar and SMTP availability. Separate from readiness so that ML or email degradation does not block container startup.

**Response 200 (all healthy):**
```json
{
  "status": "UP",
  "checks": {
    "mlSidecar": "UP",
    "email": "UP"
  },
  "version": "1.0.0"
}
```

**Response 200 (degraded — ML in fallback, still serving):**
```json
{
  "status": "UP",
  "checks": {
    "mlSidecar": "DEGRADED",
    "email": "UP"
  },
  "version": "1.0.0"
}
```
> `mlSidecar: DEGRADED` means the circuit breaker is OPEN; rules-only scoring is active.
> The application is still functional — 200 is correct; do not alert on DEGRADED alone.

**Response 503 (critical dependency down):**
```json
{
  "status": "DOWN",
  "checks": {
    "mlSidecar": "DOWN",
    "email": "DOWN"
  },
  "version": "1.0.0"
}
```

**Errors:** 503 (one or more critical dependencies unreachable)

---

## 1. Authentication & User Management

> **Auth is web-form (session cookie), not a JSON REST API.** v1 authentication is
> implemented with **Jakarta Security / Soteria `@CustomFormAuthenticationMechanismDefinition`**
> (`SecurityConfig`) — a server-rendered login form that submits to the container's
> `SecurityContext.authenticate(...)` and establishes an `HttpSession` (`JSESSIONID`
> cookie). Registration, login, logout, and password reset are **Jakarta MVC (Krazo)
> web controllers** (`AuthWebController`, `@Controller @Path("/")`) that consume
> `application/x-www-form-urlencoded` form fields and respond with a **302 redirect or a
> re-rendered JSP** — never a JSON envelope. This is deliberate: the product ships a
> JSP/HTMX server-rendered UI (see ADR-0004), and all `/api/v1/*` REST resources are
> protected by the same session cookie the login form issues.
>
> The **only** JSON REST endpoint under `/api/v1/auth/*` is `DELETE /auth/me`
> (GDPR erasure, documented below). There is **no** *v1* `POST /auth/login`, `POST
> /auth/register`, `GET /auth/me`, or `PUT /auth/password/change` REST endpoint —
> `openapi.yaml` documents JSON equivalents of these, but every one is explicitly
> annotated *"v2 pre-positioning — NOT served in v1"* (mirroring `POST /auth/login`),
> so no generator or client should treat them as callable v1 endpoints. A
> programmatic client authenticates by POSTing credentials to the web login form and
> reusing the resulting `JSESSIONID` cookie on subsequent `/api/v1/*` calls (this is
> exactly what the CI smoke test `SmokeIT` does). Machine-to-machine bearer-token auth
> (`api_token`, V19) is pre-positioned in the schema but **deferred to v2** — no token
> HTTP path exists.

### POST /register  *(web form)*
Register a new user account. Krazo controller `AuthWebController#register`.

Passwords are hashed using BCrypt with cost factor 12 (`BCRYPT_COST=12`).

| Form field | Type | Required | Validation |
|-------|------|----------|------------|
| username | string | yes | 3-50 chars, alphanumeric + underscore |
| email | string | yes | valid email format |
| password | string | yes | min 12 chars; no composition requirements; must not appear in known breach datasets (HIBP k-anonymity check) |

**Content-Type:** `application/x-www-form-urlencoded`

**Success:** `302 → /login?registered` (the new account must then log in). **Failure:** re-renders `auth/register.jsp` with an `error` model attribute (validation failure, or username/email already taken). No JSON body is returned in either case.

---

### GET /login · POST /login  *(web form, Soteria CustomForm)*
`GET /login` renders `auth/login.jsp` (optional `?next=` for post-login redirect, guarded by the `SafeRedirects` allowlist; `?registered` / `?reset` flash banners). `POST /login` submits `username` + `password` (+ optional `next`) to `SecurityContext.authenticate(...)`.

**Content-Type:** `application/x-www-form-urlencoded`

**Outcomes:**
- `SUCCESS` → `302` to the validated `next` target (default `/dashboard`); `JSESSIONID` session cookie established.
- `SEND_CONTINUE` → the mechanism has already committed its own redirect response.
- invalid credentials / disabled / locked → re-renders `auth/login.jsp` with a generic `"Invalid username or password."` error (the mechanism does not leak which of the three occurred to the form; account lockout after 5 failures is still enforced server-side per §Authentication Security — a locked account cannot authenticate for 15 min).

There is no JSON login response and no `401/403/423` status code returned to a form client — the CustomForm mechanism re-presents the login page instead.

---

### POST /logout  *(web form)*
Invalidates the current `HttpSession` (`AuthWebController#logout`) and redirects to the public landing page. Requires an authenticated session.

**Success:** `302` redirect. No content body.

---

### DELETE /auth/me  *(the one REST endpoint)*
GDPR account deletion. Permanently deletes the account and anonymizes references. Requires current password to prevent CSRF-triggered deletions. All active sessions are invalidated.

Behaviour:
1. Validate `currentPassword` — reject 422 if wrong.
2. Execute a hard `DELETE` on the `secbret_user` row.
3. Database cascades execute automatically:
   - `api_token`, `password_reset_token`, `idempotency_key`, `webhook_subscription` are CASCADE DELETED.
   - `scan_job`, `user_report`, `report_job`, `share_link`, `security_team_review` have their user FKs set to NULL via `ON DELETE SET NULL`.
   - `audit_log.actor_id` is set to NULL. The `actor_username` string field retains the `deleted_{uuid}` tombstone for historical context.
4. Invalidate all sessions for this user.
5. Return 204.

> **DB trigger note:** The `actor_username` tombstone on `audit_log` rows is written
> atomically by the V20 trigger `tombstone_audit_before_delete` (BEFORE DELETE on
> `secbret_user`), which fires before the `ON DELETE SET NULL` cascade. Application code
> must not add a redundant UPDATE for this step. See `Part IV` §V20 for the
> trigger DDL and ordering guarantees.

| Field | Type | Required | Validation |
|-------|------|----------|------------|
| currentPassword | string | yes | Must match stored hash |

**Request:**
```json
{ "currentPassword": "MyP@ssw0rd123" }
```

**Response 204:** No content

**Errors:** 401, 422 (wrong password)

> Repeated wrong-password attempts on this endpoint DO NOT count toward the `failed_login_attempts` counter and do NOT trigger account lockout. This is by design (the user is already authenticated), but note that this endpoint does not provide a password guessing oracle because the attacker must already be authenticated as the target user.

---

### GET /forgot-password · POST /forgot-password  *(web form)*
Request a password reset email (`AuthWebController#forgotPassword`). `GET` renders `auth/forgot-password.jsp`; `POST` submits the `email` form field. **Always** re-renders "if an account exists, a reset link has been sent" regardless of email validity, account state, or SMTP outcome — this prevents user enumeration (see `Part II` password-reset flow). Email delivery is fire-and-forget after the reset token commits, so an SMTP outage never rolls back the token nor changes the response.

| Form field | Type | Required | Validation |
|-------|------|----------|------------|
| email | string | yes | valid email format |

**Content-Type:** `application/x-www-form-urlencoded` **Success:** re-renders the generic confirmation JSP (no status distinction for known vs unknown vs disabled).

---

### GET /reset-password · POST /reset-password  *(web form)*
Complete a password reset using an emailed token (`AuthWebController#resetPassword`). The token is single-use and expires after 1 hour; only its SHA-256 hash is stored. `GET /reset-password?token=…` renders `auth/reset-password.jsp`; `POST` submits `token` + `newPassword`.

| Form field | Type | Required | Validation |
|-------|------|----------|------------|
| token | string | yes | reset token from the email link |
| newPassword | string | yes | Same policy as registration (min 12 chars, no composition requirements, HIBP check) |

**Content-Type:** `application/x-www-form-urlencoded` **Success:** `302 → /login?reset` (all of the user's outstanding reset tokens are then invalidated). **Failure:** re-renders `auth/reset-password.jsp` with an error when the token is invalid, expired, already used, or the new password fails policy.

---

## 2. URL Scanning

### POST /scan
Submit a URL for scanning. Returns immediately with a job ID. Processing is async. If a PENDING or RUNNING job already exists for this URL, it is marked SUPERSEDED and a new job is created. The superseded job's `GET /scan/{jobId}` response includes a `supersededBy` field pointing to the new job.

> **DB trigger note:** The `superseded_by` linkage is set atomically by the V20 database
> trigger `link_superseded_scan_job` (AFTER INSERT on `scan_job`). Application code must
> not duplicate this step. See `Part IV` §V20 for the trigger DDL.

**Roles:** REPORTER, ANALYST, ADMIN

**Idempotency:** Supports `Idempotency-Key` header for safe retries.

| Field | Type | Required | Validation |
|-------|------|----------|------------|
| url | string | yes | valid HTTP(S) URL, max 2048 chars, no private IPs |
| | | | The URL is normalized before deduplication using the algorithm defined in `Part II` §C (8-step normalization, SHA-256 hash). The original URL is stored and returned in all API responses. |
| depth | string | no | `QUICK` (default) or `DEEP` — normalized to uppercase before persistence; API accepts both cases |

**Request:**
```json
{
  "url": "https://suspicious-site.com/login",
  "depth": "DEEP"
}
```

**Response 202:**
```json
{
  "jobId": "f7e8d9c0-...",
  "urlId": "u1v2w3x4-...",
  "url": "https://suspicious-site.com/login",
  "depth": "DEEP",
  "status": "PENDING",
  "createdAt": "2026-06-17T10:00:00Z"
}
```

**Errors:** 400 (invalid URL, private IP, malformed), 401, 429 (rate limited)

---

### GET /scan/{jobId}
Poll the status and result of a scan job.

**Roles:** REPORTER (own jobs), ANALYST, ADMIN (all jobs)

**Response 200 (pending/running):**
```json
{
  "jobId": "f7e8d9c0-...",
  "urlId": "u1v2w3x4-...",
  "url": "https://suspicious-site.com/login",
  "depth": "DEEP",
  "status": "RUNNING",
  "createdAt": "2026-06-17T10:00:00Z",
  "startedAt": "2026-06-17T10:00:02Z"
}
```

**Response 200 (completed):**
```json
{
 "jobId": "f7e8d9c0-...",
	"urlId": "u1v2w3x4-...",
	"url": "https://suspicious-site.com/login",
  "depth": "DEEP",
  "status": "COMPLETED",
  "createdAt": "2026-06-17T10:00:00Z",
  "completedAt": "2026-06-17T10:00:15Z",
  "result": {
    "id": "r1s2t3u4-...",
    "overallScore": 0.87,
    "tier1Findings": {
      "domainAge": "3_days",
      "sslValid": false,
      "sslExpiryDate": null,
      "httpHeaders": {
        "xFrameOptions": "missing",
        "contentSecurityPolicy": "missing",
        "strictTransportSecurity": "missing"
      },
      "dnsRecords": ["1.2.3.4"],
      "redirectChain": ["https://suspicious-site.com/login"]
    },
    "tier2Findings": {
      "hasLoginForm": true,
      "hasBrandLogo": true,
      "suspiciousScripts": 3,
      "externalDomains": ["evil-cdn.com"],
      "hiddenIframes": 1,
      "contentSizeBytes": 45230
    },
    "tier3Findings": {
      "knownPhishingKit": true,
      "kitRulesetVersion": "2026.07.1",
      "outdatedLibraries": ["jquery-1.6.3"],
      "cveMatches": ["CVE-2021-12345"],
      "openRedirect": false
    }
  }
}
```

**Response 200 (failed):**
```json
{
  "jobId": "f7e8d9c0-...",
	  "urlId": "u1v2w3x4-...",
  "url": "https://unreachable-site.com",
  "depth": "QUICK",
  "status": "FAILED",
  "errorMessage": "Connection timed out after 5000ms",
  "createdAt": "2026-06-17T10:00:00Z"
}
```

**Response 200 (superseded — replaced by a newer scan):**
```json
{
  "jobId": "f7e8d9c0-...",
	  "urlId": "u1v2w3x4-...",
  "url": "https://suspicious-site.com",
  "depth": "QUICK",
  "status": "SUPERSEDED",
  "supersededBy": "a1b2c3d4-...",
  "createdAt": "2026-06-17T10:00:00Z"
}
```

**Errors:** 401, 404 (job not found or not owned by caller — see §Conventions Authorization)

---

### GET /scan/url/{urlId}
Get the latest consolidated scan result for a URL.

**Roles:** REPORTER, ANALYST, ADMIN

**Authorization Note:** REPORTERs are restricted to URLs they have previously scanned; a `urlId` they've never scanned returns 404 (ownership is concealed, per §A.2 — not repeated here).

**Response 200:**
```json
{
  "urlId": "u1v2w3x4-...",
  "url": "https://suspicious-site.com/login",
  "communityVerdict": "MALICIOUS",
  "lastScannedAt": "2026-06-17T10:00:15Z",
  "latestResult": { "...same as result above..." }
}
```

**Errors:** 401 Unauthorized, 404 Not Found

---

### GET /scan
List scan jobs. REPORTERs see their own jobs only. ANALYSTs and ADMINs may pass `all=true` to list across all users.

**Roles:** REPORTER, ANALYST, ADMIN

| Query Param | Type | Default | Description |
|-------------|------|---------|-------------|
| status | string | all | Filter by status (PENDING, RUNNING, COMPLETED, SUPERSEDED, FAILED) |
| depth | string | all | Filter by depth (QUICK, DEEP) |
| all | boolean | false | ANALYST / ADMIN only — return jobs for all users. Returns 403 if a REPORTER passes `true`. |
| page | int | 1 | Page number |
| size | int | 20 | Items per page (max 100) |

**Response 200:**
```json
{
  "scans": [
    {
      "jobId": "f7e8d9c0-...",
      "urlId": "u1v2w3x4-...",
      "url": "https://suspicious-site.com/login",
      "depth": "DEEP",
      "status": "COMPLETED",
      "createdAt": "2026-06-17T10:00:00Z",
      "completedAt": "2026-06-17T10:00:15Z"
    }
  ],
  "totalElements": 42,
  "totalPages": 3,
  "currentPage": 1,
  "pageSize": 20
}
```

**Errors:** 401

---

## 3. Incident Reporting

### POST /incident
Submit an incident report for a URL. Triggers SecBret AI analysis.

**Roles:** REPORTER, ANALYST, ADMIN

**Prerequisite:** The URL does not need a prior scan to be reported. If no `scan_result` exists for the URL, the rules engine runs with empty Tier 1–3 findings, producing a degraded score. A warning is included in the reasoning chain: "No prior scan data available; analysis is based on user evidence only."

**Idempotency:** Supports `Idempotency-Key` header for safe retries. Duplicate requests with the same key and identical body return the original response for 24 hours. Different body with the same key returns 409.

| Field | Type | Required | Validation |
|-------|------|----------|------------|
| url | string | yes | valid HTTP(S) URL, max 2048 chars |
| evidenceDescription | string | yes | 10-2000 chars |
| evidenceUrls | string[] | no | max 5 URLs, each max 2048 chars |

**Request:**
```json
{
  "url": "https://phishing-site.com/bank-login",
  "evidenceDescription": "This site mimics Bank of America login page...",
  "evidenceUrls": [
    "https://legitimate-bank.com/real-login",
    "https://web.archive.org/snapshot/..."
  ]
}
```

> `evidenceUrls`: Each URL is validated with the same rules as `url` (valid HTTP/HTTPS, max 2048 chars, **no private IPs**). Invalid URLs in the array result in a `400 Bad Request` with the index of the first invalid URL.

**Response 202:**
```json
{
  "reportId": "b1c2d3e4-...",
  "urlId": "u1v2w3x4-...",
  "status": "PENDING",
  "createdAt": "2026-06-17T10:00:00Z"
}
```

**Errors:** 400, 401, 409 (duplicate idempotency key), 429

---

### GET /incident/{reportId}
Get the current status of an incident report, including SecBret analysis and security team review.

**Roles:** REPORTER (own), ANALYST, ADMIN (all)

**Response 200 (pending: analysis not yet run):**
```json
{
 "reportId": "b1c2d3e4-...",
 "url": "https://phishing-site.com/bank-login",
 "status": "PENDING",
 "createdAt": "2026-06-17T10:00:00Z"
}
```
No `secbretAnalysis` or `securityTeamReview` -- background job has not completed yet.

**Response 200 (pending review):**
```json
{
  "reportId": "b1c2d3e4-...",
  "url": "https://phishing-site.com/bank-login",
  "status": "PENDING_REVIEW",
  "evidenceDescription": "This site mimics...",
  "evidenceUrls": ["..."],
  "secbretAnalysis": {
    "threatScore": 0.72,
    "verdict": "SUSPICIOUS",
    "reasoningChain": "1. Domain registered 2 days ago (weight: 0.3). 2. SSL certificate self-signed (weight: 0.2). 3. HTML contains homoglyph characters in domain (weight: 0.15). 4. Form action posts to external domain (weight: 0.25). 5. ML model confidence: 0.68 (weight: 0.1).",
    "mlConsulted": true,
    "mlScore": 0.68,
    "modelVersion": "xgboost-v2.1"
  },
  "createdAt": "2026-06-17T10:00:00Z"
}
```

**Response 200 (auto-verified):**
```json
{
  "reportId": "b1c2d3e4-...",
  "url": "https://phishing-site.com/bank-login",
  "status": "VERIFIED",
  "finalVerdict": "VERIFIED_MALICIOUS",
  "secbretAnalysis": {
    "threatScore": 1.00,
    "verdict": "SUSPICIOUS",
    "reasoningChain": "...",
    "mlConsulted": false,
    "mlScore": null,
    "modelVersion": null
  },
  "resolvedAt": "2026-06-17T10:00:05Z",
  "createdAt": "2026-06-17T10:00:00Z"
}
```

> **Why `threatScore` is exactly `1.00` here.** With `mlConsulted: false`, the only
> rules-only path to `combinedScore ≥ 0.95` is the Part II §7 Stage-1 dispositive
> override (`knownPhishingKit` + dispositive-eligible marker → `ruleScore = 1.0`).
> The non-dispositive weighted average is capped below the auto-block threshold, so
> a rules-only auto-`VERIFIED_MALICIOUS` always carries `threatScore = 1.00` — no
> other value is reachable on this path. Per the verdict-derivation rule (Part II
> §7 Auto-Action Thresholds), `secbretAnalysis.verdict` is still the tentative
> `SUSPICIOUS` (scores > 0.05 always map to `SUSPICIOUS`); the final disposition
> lives in `finalVerdict` only.

**Response 200 (human-reviewed):**
```json
{
  "reportId": "b1c2d3e4-...",
  "url": "https://phishing-site.com/bank-login",
  "status": "VERIFIED",
  "finalVerdict": "VERIFIED_MALICIOUS",
  "secbretAnalysis": {
    "threatScore": 0.72,
    "verdict": "SUSPICIOUS",
    "reasoningChain": "...",
    "mlConsulted": true,
    "mlScore": 0.68,
    "modelVersion": "xgboost-v2.1"
  },
  "securityTeamReview": {
    "id": "s1t2u3v4-...",
    "reviewedBy": "analyst_jane",
    "status": "APPROVED",
    "finalVerdict": "VERIFIED_MALICIOUS",
    "reviewerNotes": "Confirmed phishing kit targeting Bank of America customers. Domain WHOIS confirms 2-day registration. Recommended for blocklist.",
    "reviewedAt": "2026-06-17T14:30:00Z"
  },
  "resolvedAt": "2026-06-17T14:30:00Z",
  "createdAt": "2026-06-17T10:00:00Z"
}
```

**Response 200 (async analysis failed):**
```json
{
  "reportId": "b1c2d3e4-...",
  "url": "https://phishing-site.com/bank-login",
  "status": "FAILED",
  "errorCode": "ANALYSIS_FAILED",
  "message": "Analysis could not be completed.",
  "evidenceDescription": "This site mimics...",
  "evidenceUrls": ["..."],
  "createdAt": "2026-06-17T10:00:00Z"
}
```

**Errors:** 401, 403, 404

---

### GET /incident
List incident reports. REPORTERs see their own reports only. ANALYSTs and ADMINs may pass `all=true` to list across all users.

**Roles:** REPORTER, ANALYST, ADMIN

| Query Param | Type | Default | Description |
|-------------|------|---------|-------------|
| status | string | all | Filter by status |
| all | boolean | false | ANALYST/ADMIN only — return reports for all users. Returns 403 for REPORTER. |
| page | int | 1 | Page number |
| size | int | 20 | Items per page (max 100) |

**Response 200:**
```json
{
  "reports": [
    { "...report summary..." }
  ],
  "totalElements": 42,
  "totalPages": 3,
  "currentPage": 1,
  "pageSize": 20
}
```

---

## 4. Report Generation

### POST /report-jobs/{urlId}
Request async PDF report generation for a URL. The `{urlId}` path parameter is the id of the target `scanned_url`; the response contains the newly created report `jobId` which is then used to poll `GET /report-jobs/{jobId}`.

**Roles:** REPORTER, ANALYST, ADMIN

**Response 202:**
```json
{
  "jobId": "g1h2i3j4-...",
  "urlId": "u1v2w3x4-...",
  "status": "PENDING",
  "createdAt": "2026-06-17T10:00:00Z"
}
```

**Side Effect:** On successful PDF generation, a share link is automatically created with a 30-day expiry. The completed `GET /report-jobs/{jobId}` response includes this auto-created link. Use `POST /share` to create additional share links with custom expiry.

**Idempotent de-dup (one active job per URL):** the `uq_report_job_active_per_url` partial unique index (Part IV) permits at most one `PENDING`/`GENERATING` report job per URL. If a second `POST /report-jobs/{urlId}` arrives while one is still in flight, `ReportGenerationService` catches the `ConstraintViolationException` and returns the **existing** active job — the same `202` envelope with the in-flight `jobId`, not a new job and not a `409`. Clients that receive a `jobId` for a URL they just requested should treat it as the canonical job to poll. (This mirrors the C2 scan-job supersede pattern.)

**Errors:** 401, 404 (urlId not found), 429

---

### GET /report-jobs/{jobId}
Poll the status of a report generation job.

> **Path parameter:** `{jobId}` is the report job UUID returned in the `jobId` field of the
> `POST /report-jobs/{urlId}` response — **not** the `urlId` of the scanned URL.
> Passing a `urlId` here will return 404.
> The POST and GET use different path parameters intentionally: POST is addressed by URL
> (`{urlId}`) because it creates a job for a URL; GET is addressed by job (`{jobId}`)
> because you are polling a specific async job.

**Response 200 (generating):**
```json
{
  "jobId": "g1h2i3j4-...",
  "urlId": "u1v2w3x4-...",
  "status": "GENERATING",
  "createdAt": "2026-06-17T10:00:00Z"
}
```

**Response 200 (completed):**
```json
{
  "jobId": "g1h2i3j4-...",
  "urlId": "u1v2w3x4-...",
  "status": "COMPLETED",
  "shareLink": {
    "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "downloadUrl": "/api/v1/share/a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "htmlViewUrl": "/share/a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "expiresAt": "2026-07-17T10:00:00Z"
  },
  "fileSizeBytes": 245760,
  "completedAt": "2026-06-17T10:00:08Z",
  "createdAt": "2026-06-17T10:00:00Z"
}
```

**Response 200 (failed):**
```json
{
  "jobId": "g1h2i3j4-...",
  "urlId": "u1v2w3x4-...",
  "status": "FAILED",
  "errorMessage": "OpenPDF rendering error: ...",
  "createdAt": "2026-06-17T10:00:00Z"
}
```

**Errors:** 401, 404 (jobId not found or not owned by caller — see §Conventions Authorization)

---

## 5. Share Links

### GET /share/{uuid}
Access a shared report via UUID. No authentication required.

**Auth:** None (public, read-only)

**Response 200:**
- `Accept: application/json` → returns JSON summary
- `Accept: application/pdf` **or** query `?format=pdf` → returns PDF file download

> `?format=pdf` exists because a browser `<a href>` download link cannot set the
> `Accept` header; Accept-based negotiation alone can never serve the PDF to a
> plain link. The web views (`share/view.jsp`, `report/status.jsp`) use it.

**JSON Response:**
```json
{
  "shareUuid": "a1b2c3d4-...",
  "url": "https://suspicious-site.com/login",
  "generatedAt": "2026-06-17T10:00:08Z",
  "expiresAt": "2026-07-17T10:00:00Z",
  "executiveSummary": {
    "threatScore": 0.87,
    "verdict": "VERIFIED_MALICIOUS",
    "secbretReasoning": "...",
    "securityTeamNotes": "..."
  },
  "technicalFindings": {
    "tier1": { "..." },
    "tier2": { "..." },
    "tier3": { "..." }
  }
}
```

**PDF Response:**
```
Content-Type: application/pdf
Content-Disposition: attachment; filename="secbret-report-a1b2c3d4.pdf"
Content-Length: 245760
```

**Errors:** 404 (not found), 410 (expired or revoked)

---

### DELETE /share/{uuid}
Revoke a share link.

**Roles:** REPORTER (own links), ANALYST (all links), ADMIN (all links)

> Requires `X-CSRF-Token` header (see §Conventions — CSRF Protection).

**Response 204:** No content

**Errors:** 401, 403, 404

---

### POST /share
Create a share link for an existing completed report job.

**Roles:** REPORTER (own report jobs), ANALYST, ADMIN

**Authorization:** REPORTER may only create share links for report jobs where `requested_by` equals their own user ID. ANALYST and ADMIN may create share links for any COMPLETED report job.

| Field | Type | Required | Validation |
|-------|------|----------|------------|
| reportJobId | string | yes | UUID of a COMPLETED report job |
| expiryDays | int | no | 1-365, default configured value (30) |

**Request:**
```json
{
  "reportJobId": "g1h2i3j4-...",
  "expiryDays": 60
}
```

**Response 201:**
```json
{
  "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "downloadUrl": "/api/v1/share/a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "htmlViewUrl": "/share/a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "expiresAt": "2026-08-16T10:00:00Z"
}
```

**Errors:** 400, 401, 404 (reportJobId not found or not completed)

---

### GET /share
List share links created by the current user.

**Roles:** REPORTER, ANALYST, ADMIN

| Query Param | Type | Default | Description |
|-------------|------|---------|-------------|
| page | int | 1 | Page number |
| size | int | 20 | Items per page (max 100) |

**Response 200:**
```json
{
  "shareLinks": [
    {
      "uuid": "a1b2c3d4-e5f6-...",
      "url": "https://suspicious-site.com/login",
      "reportJobId": "g1h2i3j4-...",
      "createdAt": "2026-06-17T10:00:00Z",
      "expiresAt": "2026-07-17T10:00:00Z",
      "isRevoked": false,
      "accessCount": 3
    }
  ],
  "totalElements": 2,
  "totalPages": 1,
  "currentPage": 1,
  "pageSize": 20
}
```

**Errors:** 401

---

## 6. Admin / Security Team

### GET /admin/reviews/pending
List all incident reports pending human review.

**Roles:** ANALYST, ADMIN

| Query Param | Type | Default | Description |
|-------------|------|---------|-------------|
| page | int | 1 | Page number |
| size | int | 20 | Items per page |
| sortBy | string | createdAt | Sort field. `createdAt` sorts by report submission time. `reportedAt` is a deprecated alias for `createdAt` retained for compatibility — prefer `createdAt` in new integrations. |
| sortOrder | string | asc | asc or desc |

**Response 200:**
```json
{
  "pendingReviews": [
    {
      "reportId": "b1c2d3e4-...",
      "url": "https://phishing-site.com/...",
      "threatScore": 0.72,
      "verdict": "SUSPICIOUS",
      "reportedBy": "user123",
      "reportedAt": "2026-06-17T10:00:00Z"
    }
  ],
  "totalElements": 5,
  "totalPages": 1,
  "currentPage": 1,
  "pageSize": 20
}
```

**Errors:** 401, 403

---

### GET /admin/reviews/{reportId}
Get full details of a pending review (SecBret analysis + raw scan + user evidence).

**Roles:** ANALYST, ADMIN

**Response 200:**
```json
{
  "reportId": "b1c2d3e4-...",
  "url": "https://phishing-site.com/bank-login",
  "reportedBy": {
    "id": "...",
    "username": "user123"
  },
  "evidence": {
    "description": "...",
    "urls": ["..."]
  },
  "secbretAnalysis": {
    "threatScore": 0.72,
    "verdict": "SUSPICIOUS",
    "reasoningChain": "...",
    "mlConsulted": true,
    "mlScore": 0.68,
    "modelVersion": "xgboost-v2.1"
  },
  "scanResult": { "...full scan result..." }
}
```

**Errors:** 401, 403, 404

---

### POST /admin/reviews/{reportId}
Submit a security team review for an incident report.

**Roles:** ANALYST, ADMIN

| Field | Type | Required | Validation |
|-------|------|----------|------------|
| action | string | yes | APPROVE, REJECT, MODIFY |
| finalVerdict | string | conditional | **Required if `MODIFY`** — one of: VERIFIED_MALICIOUS, VERIFIED_BENIGN. **Omitted/ignored for `REJECT`** (sets `user_report.verdict = REJECTED`). For `APPROVE`, the AI tentative verdict is adopted and `finalVerdict` is not supplied. |
| reviewerNotes | string | no | 0-5000 chars |

**Request (Approve):**
```json
{
  "action": "APPROVE",
  "reviewerNotes": "Confirmed phishing. Recommend blocklist addition."
}
```

**Request (Modify):**
```json
{
  "action": "MODIFY",
  "finalVerdict": "VERIFIED_BENIGN",
  "reviewerNotes": "False positive. Legitimate site with poor SSL config."
}
```

**Response 200:**
```json
{
  "reviewId": "s1t2u3v4-...",
  "reportId": "b1c2d3e4-...",
  "reviewedBy": "analyst_jane",
  "status": "APPROVED",
  "finalVerdict": "VERIFIED_MALICIOUS",
  "reviewedAt": "2026-06-17T14:30:00Z"
}
```

> **Note:** The 0.50 threshold for APPROVE is the default. It can be adjusted via the `AUTO_APPROVE_ANALYST_THRESHOLD` environment variable. An analyst who agrees with a borderline AI assessment should use MODIFY with an explicit finalVerdict instead.

**Errors:** 400 (invalid action), 401, 403, 404, 409 (already reviewed)

---

### GET /admin/users
List all users. Admin only.

**Roles:** ADMIN

| Query Param | Type | Default | Description |
|-------------|------|---------|-------------|
| role | string | all | Filter by role |
| enabled | boolean | all | Filter by enabled status |
| page | int | 1 | |
| size | int | 20 | |

**Response 200:**
```json
{
  "users": [
    {
      "id": "...",
      "username": "jdoe",
      "email": "jdoe@example.com",
      "role": "REPORTER",
      "enabled": true,
      "createdAt": "..."
    }
  ],
  "totalElements": 15,
  "totalPages": 1,
  "currentPage": 1,
  "pageSize": 20
}
```

**Errors:** 401, 403

---

### PUT /admin/users/{userId}/role
Change a user's role.

**Roles:** ADMIN

**Request:**
```json
{
  "role": "ANALYST"
}
```

**Response 200:**
```json
{
  "id": "...",
  "username": "jdoe",
  "role": "ANALYST",
  "enabled": true
}
```

**Errors:** 401, 403, 404

---

### PUT /admin/users/{userId}/status
Enable or disable a user.

**Roles:** ADMIN

**Note:** This endpoint toggles `enabled` only. It does not reset lockout state.

An ADMIN may not disable their own account (returns 409 Conflict).

To unlock a locked account before the 15-minute window expires, use `PUT /admin/users/{userId}/unlock` (see below).

**Request:**
```json
{
  "enabled": false
}
```

**Response 200:**
```json
{
  "id": "...",
  "username": "jdoe",
  "role": "REPORTER",
  "enabled": false
}
```

**Errors:** 401, 403, 404, 409 (cannot disable self)

---

### PUT /admin/users/{userId}/unlock
Manually unlock a locked user account before the 15-minute lockout window expires. Resets `failed_login_attempts` to 0 and clears `locked_until`.

**Roles:** ADMIN

**Response 200:**
```json
{
  "id": "...",
  "username": "jdoe",
  "role": "REPORTER",
  "enabled": true,
  "lockedUntil": null,
  "failedLoginAttempts": 0
}
```

**Errors:** 401, 403, 404

---

### GET /admin/users/{userId}
Get the full profile of a single user by ID.

**Roles:** ADMIN

**Response 200:**
```json
{
  "id": "...",
  "username": "jdoe",
  "email": "jdoe@example.com",
  "role": "REPORTER",
  "enabled": true,
  "lockedUntil": null,
  "failedLoginAttempts": 0,
  "createdAt": "2026-06-17T10:00:00Z"
}
```

**Errors:** 401, 403, 404

---

## 7. Public Dashboard

### GET /dashboard/public
No auth required. Returns top verified malicious and benign URLs.

| Query Param | Type | Default | Description |
|-------------|------|---------|-------------|
| verdict | string | all | Filter domain is exactly `MALICIOUS`, `BENIGN` (or omitted = both). `SUSPICIOUS` and `UNKNOWN` are deliberately not filterable — `SUSPICIOUS` is never written in v1 and `UNKNOWN`/NULL entries are not surfaced on the public dashboard. Any other value → 400 |
| url | string | - | If provided, return the matching entry if it has a community verdict, or 404 otherwise. This is the primary entry point for anonymous users checking a specific URL. |
| page | int | 1 | |
| size | int | 20 | max 50 |

**Response 200:**
```json
{
  "urls": [
    {
      "url": "https://phishing-site.com/...",
      "communityVerdict": "MALICIOUS",
      "threatScore": 0.97,
      "lastScannedAt": "2026-06-17T10:00:00Z"
    }
  ],
  "totalElements": 120,
  "totalPages": 6,
  "currentPage": 1,
  "pageSize": 20
}
```

---

**Query parameter `url` (optional):** `GET /dashboard/public?url=https://suspicious.example.com`

Returns the matching entry if it has a community verdict, or 404 otherwise. **Response 200:**
```json
{
  "url": "https://phishing-site.com/...",
  "communityVerdict": "MALICIOUS",
  "threatScore": 0.97,
  "secbretReasoning": "...",
  "lastScannedAt": "2026-06-17T10:00:00Z"
}
```

**Errors:** 404 (URL not found or no community verdict)

---

## 8. Error Responses

Errors follow this envelope:

```json
{
  "status": 400,
  "error": "Bad Request",
  "message": "URL is not a valid HTTP/HTTPS URL",
  "timestamp": "2026-06-17T10:00:00Z",
  "path": "/api/v1/scan",
  "correlationId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

| Status | When |
|--------|------|
| 400 | Validation errors, malformed input |
| 401 | Unauthenticated |
| 403 | Insufficient role (RBAC) |
| 404 | Resource not found |
| 409 | Conflict (duplicate, already reviewed) |
| 410 | Share link expired or revoked |
| 423 | **Reserved — never returned in v1.** Account locked (too many failed login attempts). Login is a web form (Soteria CustomForm) that re-presents the login page instead of returning a status; no v1 endpoint emits 423. Kept in the contract (and in `openapi.yaml`) for a future JSON auth API, parallel to the pre-positioned `bearerAuth` scheme. |
| 429 | Rate limit exceeded (includes `Retry-After` header) |
| 500 | Internal server error |

---

### Request Correlation

All requests are traced via the `X-Correlation-Id` header. If the client does not supply this header, the server generates a UUID and uses it for the lifetime of the request. The correlation ID is echoed in the `X-Correlation-Id` **response** header on every reply.

| Aspect | Detail |
|--------|--------|
| Header name | `X-Correlation-Id` |
| Server behaviour | Generated server-side as UUID v4 if absent in the request; echoed back in the response header regardless |
| Purpose | Debug tracing across the full pipeline: scan → ML sidecar → report generator |
| Error responses | Every structured JSON error response includes the correlation ID as a `correlationId` field so support staff can cross-reference server logs |
| Downstream propagation | Forwarded in all outgoing calls: gRPC metadata to the ML sidecar, `X-Correlation-Id` header on HIBP API checks, and SMTP dispatch; logged in SLF4J/Logback via `MDC key correlationId` |

> For the full specification of MDC propagation and gRPC metadata handling, see
> `Part II` §9.5.

---

## 9. Enumerations

### UserRole
| Value | Description |
|-------|-------------|
| `REPORTER` | Standard user. Can submit scans, reports, generate PDFs |
| `ANALYST` | Security team member. Can review incidents |
| `ADMIN` | Full access. User management + all ANALYST rights |

### ScanDepth
| Value | Description |
|-------|-------------|
| `QUICK` | Tier 1 only (passive: DNS, SSL, WHOIS, headers) |
| `DEEP` | Tier 1 + 2 + 3 (passive + active HTML + vulnerability matching) |

### ScanJobStatus
| Value | Description |
|-------|-------------|
| `PENDING` | Job queued, awaiting execution |
| `RUNNING` | Currently executing scan tiers |
| `COMPLETED` | Scan finished, results available |
| `SUPERSEDED` | Job was replaced by a newer scan request for the same URL; see `supersededBy` field |
| `FAILED` | Scan failed due to timeout, unreachable target, or internal error |

### ReportStatus
| Value | Description |
|-------|-------------|
| `PENDING` | Submitted; SecBret async analysis not yet run |
| `PENDING_REVIEW` | AI analysis complete; score in uncertain zone; awaiting human analyst |
| `VERIFIED` | Incident resolved — either auto-approved/rejected by AI or confirmed by human review |
| `REJECTED` | Report rejected by security team; community verdict unchanged |
| `FAILED` | Async analysis DB write failed (terminal); user must re-submit |

### Verdict (SecBret internal - `secbret_analysis.verdict`)

> ⚠️ **DEVELOPER WARNING — WRONG TABLE = SILENT DATA CORRUPTION**
>
> `secbret_analysis.verdict` is the **AI-only tentative verdict**. It is constrained to
> `BENIGN` or `SUSPICIOUS`. These values are produced by the rules engine and ML sidecar
> and represent an intermediate, uncertain assessment — not a final disposition.
>
> `VERIFIED_MALICIOUS`, `VERIFIED_BENIGN`, and `REJECTED` **must never be written here**.
> They belong exclusively on:
> - `user_report.verdict` (maps to `finalVerdict` in API responses)
> - `security_team_review.final_verdict`
>
> Writing a `VERIFIED_*` value to `secbret_analysis.verdict` will be rejected at the
> DB level by `chk_analysis_verdict`. Writing a `BENIGN`/`SUSPICIOUS` value to
> `user_report.verdict` will not be caught by the DB (the column allows both sets) but
> will break downstream verdict display and community-verdict derivation logic.
>
> The correct flow is: AI → `BENIGN`/`SUSPICIOUS` in `secbret_analysis.verdict`;
> human review or auto-resolution → `VERIFIED_*`/`REJECTED` in `user_report.verdict`
> and `security_team_review.final_verdict`.
>
> **DB constraint:** `chk_analysis_verdict CHECK (verdict IN ('BENIGN', 'SUSPICIOUS'))`.
> `VERIFIED_*` values never appear here; they live exclusively on `user_report.verdict`
> and `security_team_review.final_verdict`.

| Value | Description |
|-------|-------------|
| `BENIGN` | `combinedScore ≤ 0.05` — AI assessment: no threats |
| `SUSPICIOUS` | `combinedScore > 0.05` — uncertain or high; covers PENDING_REVIEW **and** both dispositive/auto-approved outcomes |

> **Derivation rule:** `verdict = BENIGN` iff `combinedScore ≤ 0.05`, else
> `SUSPICIOUS` — defined normatively in Part II §7 **Auto-Action Thresholds →
> Tentative-verdict derivation**. The dispositive override (`combinedScore = 1.0`)
> also writes `SUSPICIOUS` here; the auto-final `VERIFIED_MALICIOUS` goes to
> `user_report.verdict` only.

### Final Verdict (post-review - `user_report.verdict`)

> ⚠️ **DEVELOPER WARNING — VERDICT TABLE DISTINCTION**
> These values apply only **after** human review or auto-resolution.
> Do **not** write `VERIFIED_*` or `REJECTED` to `secbret_analysis.verdict` — see the
> Verdict (SecBret internal) block above. The DDL column name `verdict` on `user_report`
> maps to the `finalVerdict` field in API responses; the DTO handles the translation.
| Value | Description |
|-------|-------------|
| `VERIFIED_MALICIOUS` | Confirmed malicious by security team review |
| `VERIFIED_BENIGN` | Confirmed benign by security team review |
| `REJECTED` | Report rejected by security team (no community verdict set) |

> **Note:** The `user_report.verdict` database column maps to the `finalVerdict` field in API responses. The DDL column name differs from the API field name; the DTO handles the translation.

### CommunityVerdict (scanned_url)
| Value | Description |
|-------|-------------|
| `UNKNOWN` | URL has been seen but no verdict has been established — written at URL creation time only |
| `MALICIOUS` | Community verdict: malicious |
| `SUSPICIOUS` | **Reserved for v2** (e.g. concurrent unresolved reports); never written in v1 — see Part II §8.5. Exposed in the enum/CHECK so clients deserialize safely |
| `BENIGN` | Community verdict: benign |
| (NULL) | No community verdict yet |

### ReviewAction
| Value | Description |
|-------|-------------|
| `APPROVE` | Approve SecBret's suggested verdict |
| `REJECT` | Reject the report entirely |
| `MODIFY` | Override the AI verdict with an explicit `finalVerdict` (unlike `APPROVE`, which adopts the AI verdict via the 0.50 analyst threshold) |

> **Implementation note:** See `Part IV` for `report_job.file_data` JPA `@Lob` lazy-loading details.

### ReportJobStatus
| Value | Description |
|-------|-------------|
| `PENDING` | Report generation queued |
| `GENERATING` | PDF currently being rendered |
| `COMPLETED` | PDF ready for download |
| `FAILED` | Generation failed |

---

### JPA Soft-Delete — `@Where` Intentionally Omitted

> **Implementation note for developers:** The `scanned_url` and `user_report` entities
> carry `deleted_at` columns and partial indexes, but v1 JPA entity classes do **not**
> carry `@Where(clause = "deleted_at IS NULL")`. This omission is intentional.
>
> Because no v1 write path sets `deleted_at`, adding `@Where` now would create silent
> row-exclusion in test fixtures and migration rollbacks without providing any runtime
> benefit. Do **not** add `@Where` to v1 entities.
>
> The v2 migration path uses `@FilterDef` / `@Filter` (which can be disabled per-request
> for admin views) instead of the always-on `@Where`. See `Part II` §16 for the
> full rationale and the v2 migration plan.

---

## Rate Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| POST /scan | 10 requests | per user per hour |
| POST /incident | 5 requests | per user per hour |
| POST /report-jobs/{urlId} | 3 requests | per user per hour |
| POST /login (web form) | 10 requests | per IP per 15 minutes |
| POST /forgot-password (web form) | 5 requests | per IP per 15 minutes |
| POST /reset-password (web form) | 5 requests | per IP per 15 minutes |
| POST /share | 10 requests | per user per hour |
| GET /dashboard/public | 60 requests | per IP per minute |
| All other endpoints | 60 requests | per IP per minute |
| Auth surface (secondary backstop; see Part II §5) | 100 requests (`RATE_LIMIT_AUTH_BACKSTOP`) | per IP per hour |

> **Backstop semantics:** the auth backstop is a coarse per-IP guard applied **in
> addition to** the fine-grained rule on the same request (backstop is checked
> first; either limit alone can reject). It covers the **auth surface** — all
> `/auth/*` requests plus `POST` to the web-form auth endpoints (`/login`,
> `/register`, `/forgot-password`, `/reset-password`) — it is not a limit on all
> authenticated traffic. Its ceiling (100/h) is deliberately above every
> fine-grained auth limit so legitimate users behind a shared NAT are throttled
> by the specific rules, not the backstop.

Rate limit headers on all responses:
```
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 7
X-RateLimit-Reset: 1718618400
```

> **Note:** Login endpoint limits (`POST /login`, `POST /forgot-password`) count separately from per-account lockout.

---

## Conventions

### CSRF Protection

Because authentication is cookie-based, all authenticated state-changing requests require a valid `X-CSRF-Token` header in addition to an active session cookie. Missing or invalid CSRF tokens return `403 Forbidden`.

**Required on:** all POST, PUT, PATCH, and DELETE endpoints that require authentication.

```http
POST /scan

Cookie: JSESSIONID=...
X-CSRF-Token: abc123
```

Session cookies are set with `HttpOnly`, `Secure`, and `SameSite=Strict` attributes.

### Authorization

All endpoints that require authentication follow the authorization philosophy defined in `Part II` §A.2:
- **401 Unauthorized** — no valid session
- **403 Forbidden** — authenticated but role does not permit the action
- **404 Not Found** — resource does not exist OR caller is not authorized to know it exists (data enumeration prevention)

### NULL Tier Response (QUICK Scans)

When a QUICK scan runs only Tier 1, the API returns empty objects for Tier 2 and Tier 3, keeping the JSON response shape identical across scan depths.

```json
{
  "tier1Findings": { "...full data..." },
  "tier2Findings": {},
  "tier3Findings": {}
}
```

### Account Lockout

After 5 consecutive failed login attempts, the account is locked for 15 minutes. The lockout is enforced server-side in `AuthenticationService` — during lockout `SecurityContext.authenticate(...)` fails and the CustomForm mechanism re-presents the login page (it does not return a `423` status to a form client). A successful login resets the counter.

### Session Timeout

Authenticated sessions expire after 30 minutes of inactivity.

### Idempotency-Key

Three mutating POST endpoints support the `Idempotency-Key` request header: `POST /scan`, `POST /incident`, and `POST /report-jobs/{urlId}`. No other endpoints use idempotency keys. The `idempotency_key` table stores the scoped key per user per endpoint. When provided:

- Same key + same request body, key not in-flight → processes request, caches response for 24h
- Same key + same request body, key already has cached response → returns cached response (original status code)
- Same key + same request body, key is in-flight → returns `409 Conflict` with `Retry-After: 5`
- Same key + different request body → returns `409 Conflict`
- Key omitted → no idempotency protection, normal request processing

### HIBP Password Check

On registration (`POST /register`, web form), passwords are checked against the Have I Been Pwned k-anonymity API (range query using SHA-1 prefix). If the password suffix matches a known breach, registration is rejected (the registration form re-renders with an error). If the HIBP API is unreachable or times out (3s), the check is skipped (fail-open) to avoid blocking registration on external dependency failure; the skip is logged server-side (`BreachCheckService`). *(v1 does not surface a per-response `X-HIBP-Check` header — the fail-open decision is observable only in server logs.)*

### Renamed Paths (never shipped under the old names)

The following paths appeared under different names in earlier *drafts of this specification* and were renamed before v1 shipped. No release ever served the old paths — there is no deprecation or sunset window (SecBret exposes a single API version, v1). The table exists purely so readers of older spec drafts can map old names to current ones.

| Draft Name (never shipped) | Current Path |
|----------|----------|
| `POST /api/v1/report` | `POST /api/v1/incident` |
| `GET /api/v1/report/{id}` | `GET /api/v1/incident/{id}` |
| `GET /api/v1/report` | `GET /api/v1/incident` |
| `POST /api/v1/report/generate/{urlId}` | `POST /api/v1/report-jobs/{urlId}` |
| `GET /api/v1/report/status/{jobId}` | `GET /api/v1/report-jobs/{jobId}` |
| `GET /api/v1/report/share/{uuid}` | `GET /api/v1/share/{uuid}` |
| `DELETE /api/v1/report/share/{uuid}` | `DELETE /api/v1/share/{uuid}` |
| `GET /api/v1/report/share` | `GET /api/v1/share` |

---

## 10. Deferred to v2

The following features have been scoped out of v1. No stub endpoints exist; they will be added to the v2 OpenAPI specification.

| Feature | Planned Endpoint(s) |
|---------|---------------------|
| **Batch scan** | `POST /scan/batch` |
| **Personal API tokens** | `POST /auth/tokens`, `GET /auth/tokens`, `DELETE /auth/tokens/{id}` |
| **Webhooks** | `POST /webhooks`, `GET /webhooks`, `DELETE /webhooks/{id}`, `POST /webhooks/{id}/test` |

---

## 11. Document Cross-Reference

The following table maps each cross-cutting concern to its authoritative source and the document(s) that reference or implement it. When these documents conflict, the primary document is authoritative.

| Topic | Primary Document | Secondary Document |
|-------|------------------|--------------------|
| URL Normalization Algorithm | `Part II` §C | `Part III` §2 |
| CSRF Protection | `Part III` §Conventions | `Part II` §5 |
| Rate Limiting | `Part III` §Rate Limits | `Part II` §5 |
| Correlation IDs | `Part II` §9.5 | `Part III` §8 (Request Correlation) |
| V20 DB Triggers | `Part IV` §V20 | `Part II` §16 |
| Soft-Delete Strategy | `Part II` §16 | `Part IV` §V14 |
| ML Circuit Breaker | `Part II` §7 | `workflows.puml` (Incident Workflow) |
| Session Invalidation | `Part II` §15.5 | `workflows.puml` (GDPR Deletion) |

---

# Part IV — Database Schema

**RDBMS:** PostgreSQL 14+ **Migration Tool:** Flyway **Naming Convention:** snake_case for tables/columns, UUID primary keys

> **Canonical Ownership:** This document is the authoritative source for database structure,
> DDL, Flyway migration naming, indexes, and trigger definitions.
> Cross-cutting topics (password policy, RBAC, URL normalization, deletion strategy,
> error response format) are defined in `Part II` and `Part III`.
> See `Part II` §A.1 for the full canonical ownership matrix.

The `CREATE TABLE` blocks below show the schema in its **current, fully-migrated shape** — a readable snapshot, not the literal DDL Flyway runs. The real schema is the sum of the migrations: `V1` laid down the base tables, and everything from `V10` onward is incremental (`V11` reset tokens, `V12` webhooks, `V13` idempotency, `V14` soft-delete + optimistic-locking columns, `V16` composite/JSONB indexes, `V17`–`V18` constraint and audit additions, `V20` the concurrency and GDPR triggers). The per-migration sections later in this part carry the details of what each one added; when the snapshot and the migrations disagree, the migrations are authoritative.

The UUID and snake_case conventions were set at V1 and are load-bearing for the JPA mapping; a new migration must not introduce a `serial` PK or a camelCase column without good reason.

---

## Entity Overview

| Table | Purpose | PK Type |
|-------|---------|---------|
| `secbret_user` | User accounts and RBAC | UUID |
| `scanned_url` | Unique URLs in the system | UUID |
| `scan_job` | Async scan task tracking | UUID |
| `scan_result` | Scan findings per job | UUID |
| `user_report` | Incident reports | UUID |
| `secbret_analysis` | AI analysis output | UUID |
| `security_team_review` | Human review records | UUID |
| `report_job` | Async PDF generation jobs | UUID |
| `share_link` | UUID-based share tokens | UUID |
| `password_reset_token` | Single-use password reset tokens | UUID |
| `webhook_subscription` | Webhook endpoints (v2 pre-positioning) | UUID |
| `idempotency_key` | Idempotency key storage for safe retries | UUID |
| `audit_log` | Immutable audit trail for security actions | UUID |

---

## Table Definitions

### secbret_user

```sql
CREATE TABLE secbret_user (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username        VARCHAR(50)  NOT NULL UNIQUE,
    email           VARCHAR(255) NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,
    role            VARCHAR(20)  NOT NULL DEFAULT 'REPORTER',
    enabled         BOOLEAN      NOT NULL DEFAULT TRUE,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TIMESTAMP,
    created_at      TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP    NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_user_role CHECK (role IN ('REPORTER', 'ANALYST', 'ADMIN'))
);

CREATE INDEX idx_user_username ON secbret_user (username);
CREATE INDEX idx_user_email ON secbret_user (email);
CREATE INDEX idx_user_role ON secbret_user (role);
CREATE INDEX idx_user_locked_until ON secbret_user (locked_until) WHERE locked_until IS NOT NULL;
```

### scanned_url

```sql
CREATE TABLE scanned_url (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    original_url        VARCHAR(2048) NOT NULL,
    normalized_hash     VARCHAR(64)  NOT NULL,
    last_scanned_at     TIMESTAMP,
    community_verdict   VARCHAR(30),
    created_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMP NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_community_verdict
        CHECK (community_verdict IS NULL
            OR community_verdict IN ('UNKNOWN', 'BENIGN', 'SUSPICIOUS', 'MALICIOUS'))
);

CREATE UNIQUE INDEX uq_scanned_url_normalized_hash ON scanned_url (normalized_hash);

CREATE INDEX idx_scanned_url_verdict ON scanned_url (community_verdict);
CREATE INDEX idx_scanned_url_last_scanned ON scanned_url (last_scanned_at DESC);
```

`deleted_at` is not in the base DDL — it arrives in V14, which also replaces the hard `UNIQUE` on `normalized_hash` above with a partial unique index (`WHERE deleted_at IS NULL`). Don't pre-add the partial index here, or V14 fails with "relation already exists".

---

### scan_job

```sql
CREATE TABLE scan_job (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url_id          UUID        NOT NULL REFERENCES scanned_url(id) ON DELETE CASCADE,
    submitted_by    UUID        REFERENCES secbret_user(id) ON DELETE SET NULL,
    superseded_by   UUID        REFERENCES scan_job(id) ON DELETE SET NULL,
    scan_depth      VARCHAR(10) NOT NULL DEFAULT 'QUICK',
    status          VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    version         BIGINT      NOT NULL DEFAULT 0,
    error_message   TEXT,
    created_at      TIMESTAMP   NOT NULL DEFAULT NOW(),
    started_at      TIMESTAMP,
    completed_at    TIMESTAMP,

    CONSTRAINT chk_scan_depth CHECK (scan_depth IN ('QUICK', 'DEEP')),
    CONSTRAINT chk_scan_job_status CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'SUPERSEDED', 'FAILED'))
);

CREATE INDEX idx_scan_job_url ON scan_job (url_id);
CREATE INDEX idx_scan_job_submitted_by ON scan_job (submitted_by);
CREATE UNIQUE INDEX uq_scan_job_active_per_url
  ON scan_job (url_id)
  WHERE status IN ('PENDING', 'RUNNING');
```

`version` backs JPA `@Version` optimistic locking. `SUPERSEDED` marks a job replaced by a newer scan for the same URL (distinct from `FAILED`). The partial unique index `uq_scan_job_active_per_url` enforces the one-active-job-per-URL / overwrite invariant at the DB level; V16 adds a composite `idx_scan_job_status_created`. On the concurrency side, `createJob()` locks the `scanned_url` row (`SELECT ... FOR UPDATE`) before touching `scan_job`, and the V20 trigger `link_superseded_scan_job` sets `superseded_by` after INSERT — the application never writes the back-pointer. See Part II §1 (decision #2) and §V20.

---

### scan_result

```sql
CREATE TABLE scan_result (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url_id          UUID        NOT NULL REFERENCES scanned_url(id) ON DELETE CASCADE,
    scan_job_id     UUID        NOT NULL UNIQUE REFERENCES scan_job(id) ON DELETE CASCADE,
    tier1_findings  JSONB,
    tier2_findings  JSONB,
    tier3_findings  JSONB,
    overall_score   DECIMAL(3,2),
    created_at      TIMESTAMP   NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_overall_score CHECK (overall_score IS NULL OR (overall_score >= 0.00 AND overall_score <= 1.00))
);

CREATE INDEX idx_scan_result_url ON scan_result (url_id);
CREATE INDEX idx_scan_result_score ON scan_result (overall_score DESC);
```

V16 adds GIN indexes on `tier1/2/3_findings` for JSONB containment queries.

**JSONB Structure for tier1_findings:**
```json
{
  "domainAge": "3_days",
  "sslValid": false,
  "sslExpiryDate": null,
  "sslIssuer": "Let's Encrypt",
  "httpHeaders": {
    "xFrameOptions": "missing",
    "contentSecurityPolicy": "missing",
    "strictTransportSecurity": "missing",
    "xContentTypeOptions": "missing"
  },
  "dnsRecords": ["1.2.3.4"],
  "redirectChain": ["https://example.com/a", "https://example.com/b"],
  "whoisInfo": {
    "registrar": "Example Registrar",
    "creationDate": "2026-06-15",
    "nameservers": ["ns1.example.com"]
  }
}
```

**JSONB Structure for tier2_findings:**
```json
{
  "hasLoginForm": true,
  "hasBrandLogo": true,
  "externalDomains": ["cdn.evil.com"],
  "suspiciousScripts": 3,
  "hiddenIframes": 1,
  "contentSizeBytes": 45230,
  "forms": [
    {
      "action": "https://evil.com/post",
      "method": "POST",
      "inputFields": ["username", "password"]
    }
  ],
  "links": {
    "internal": 12,
    "external": 5
  }
}
```

**JSONB Structure for tier3_findings:**
```json
{
  "knownPhishingKit": true,
  "phishingKitName": "v19_darkside",
  "kitRulesetVersion": "2026.07.1",
  "kitMarkersMatched": [
    { "id": "KIT-0042", "dispositiveEligible": true }
  ],
  "outdatedLibraries": ["jquery-1.6.3"],
  "cveMatches": ["CVE-2021-12345"],
  "openRedirect": false,
  "directoryListing": false
}
```

`kitRulesetVersion` and `kitMarkersMatched` are REQUIRED whenever the Tier 3 kit detector ran (see §7 **Phishing-Kit Marker Governance**): they make every kit verdict traceable to the marker set and markers that produced it. `knownPhishingKit` MUST be `true` only when at least one matched marker has `dispositiveEligible: true`.

---

### user_report

> ⚠️ **C4 — VERDICT TABLE DISTINCTION**
> `user_report.verdict` stores the **final, post-resolution verdict** (`VERIFIED_MALICIOUS`,
> `VERIFIED_BENIGN`, `REJECTED`). The AI tentative verdict (`BENIGN`/`SUSPICIOUS`) lives on
> `secbret_analysis.verdict`. See the `secbret_analysis` section above for the full warning.

```sql
CREATE TABLE user_report (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url_id                  UUID        NOT NULL REFERENCES scanned_url(id) ON DELETE CASCADE,
    reported_by             UUID        REFERENCES secbret_user(id) ON DELETE SET NULL,
    evidence_description   TEXT        NOT NULL,
    evidence_urls           JSONB,
    status                  VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    verdict                 VARCHAR(30),
    error_message           TEXT,
    version                 BIGINT      NOT NULL DEFAULT 0,
    deleted_at              TIMESTAMP,
    created_at              TIMESTAMP   NOT NULL DEFAULT NOW(),
    resolved_at             TIMESTAMP,

    CONSTRAINT chk_report_status CHECK (status IN ('PENDING', 'PENDING_REVIEW', 'VERIFIED', 'REJECTED', 'FAILED')),
    CONSTRAINT chk_report_verdict CHECK (
        verdict IS NULL
        OR (
            verdict IN ('VERIFIED_MALICIOUS', 'VERIFIED_BENIGN', 'REJECTED')
            AND verdict NOT IN ('BENIGN', 'SUSPICIOUS')
        )
    ),
    CONSTRAINT chk_evidence_length CHECK (char_length(evidence_description) >= 10 AND char_length(evidence_description) <= 2000)
);

CREATE INDEX idx_user_report_url ON user_report (url_id);
CREATE INDEX idx_user_report_reported_by ON user_report (reported_by);
CREATE INDEX idx_user_report_created ON user_report (created_at DESC);
```

Column and constraint notes: `error_message` is populated when async analysis fails (§16.5); `version` backs `@Version` optimistic locking (mirrors `scan_job`); `deleted_at` is the soft-delete tombstone, covered by a partial index so live-row queries never filter it out. `chk_report_verdict` is a deliberate dual-layer guard — an `IN` allowlist of final-resolution values **and** a `NOT IN` denylist of the AI-only values (`BENIGN`/`SUSPICIOUS`), so a future migration that accidentally widens the allowlist still can't let AI-only values into this column (the C1 fix). `version` and `deleted_at` are declared inline here, so V14's `ADD COLUMN IF NOT EXISTS` is a no-op against this schema. V16 adds the composite `idx_user_report_status_created` and the partial `idx_user_report_pending_created`.

**JSONB Structure for evidence_urls:**
```json
["https://example.com/ref1", "https://example.com/ref2"]
```

---

### secbret_analysis

> ⚠️ **C4 — VERDICT TABLE DISTINCTION (read before writing to this table)**
>
> `secbret_analysis.verdict` is the **AI-only tentative verdict**. The CHECK constraint
> `chk_analysis_verdict` enforces exactly two allowed values: `'BENIGN'` and `'SUSPICIOUS'`.
>
> **Never write `VERIFIED_MALICIOUS`, `VERIFIED_BENIGN`, or `REJECTED` here.**
> Those are post-resolution values that belong on:
> - `user_report.verdict` (human or auto-resolution outcome, aliased as `finalVerdict` in the API)
> - `security_team_review.final_verdict` (analyst decision)
>
> Writing the wrong set of values to the wrong table is now **caught at the DB level for
> `user_report`** thanks to the C1 dual-layer guard on `chk_report_verdict` (V17): the
> constraint rejects `BENIGN` and `SUSPICIOUS` via a `NOT IN` clause in addition to the
> `IN` allowlist. A `VERIFIED_*` value written to `secbret_analysis.verdict` is still
> caught by `chk_analysis_verdict`. `IncidentPersistence` carries a runtime
> assertion as a second layer (see Part II §8.5 C4 table for details).
>
> **Rule of thumb:**
> - AI writes → `secbret_analysis.verdict` with `BENIGN` or `SUSPICIOUS`
> - Auto-resolution or human review writes → `user_report.verdict` and
>   `security_team_review.final_verdict` with `VERIFIED_MALICIOUS`, `VERIFIED_BENIGN`, or `REJECTED`

```sql
CREATE TABLE secbret_analysis (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url_id              UUID        NOT NULL REFERENCES scanned_url(id) ON DELETE CASCADE,
    scan_result_id      UUID        REFERENCES scan_result(id) ON DELETE SET NULL,
    user_report_id      UUID        REFERENCES user_report(id) ON DELETE SET NULL,
    threat_score        DECIMAL(3,2) NOT NULL,
    verdict             VARCHAR(30) NOT NULL,
    reasoning_chain     TEXT        NOT NULL,
    ml_consulted        BOOLEAN     NOT NULL DEFAULT FALSE,
    ml_score            DECIMAL(3,2),
    model_version       VARCHAR(50),
    created_at          TIMESTAMP   NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_threat_score CHECK (threat_score >= 0.00 AND threat_score <= 1.00),
    CONSTRAINT chk_ml_score CHECK (ml_score IS NULL OR (ml_score >= 0.00 AND ml_score <= 1.00)),
    CONSTRAINT chk_analysis_verdict CHECK (verdict IN ('BENIGN', 'SUSPICIOUS'))
);

CREATE INDEX idx_secbret_analysis_url ON secbret_analysis (url_id);
CREATE INDEX idx_secbret_analysis_report ON secbret_analysis (user_report_id);
CREATE INDEX idx_secbret_analysis_score ON secbret_analysis (threat_score DESC);

CREATE UNIQUE INDEX uq_secbret_analysis_report
    ON secbret_analysis (user_report_id)
    WHERE user_report_id IS NOT NULL;
```

`model_version` records the ML sidecar version at classification time. This table is insert-only for the AI: it never updates on top of a human review, so the earlier `verdict_set_by` / `verdict_set_at` columns and the `trg_resolve_verdict_conflict` trigger were dropped — human decisions live in `security_team_review`. The partial unique index guards against duplicate analysis rows if the async CDI event fires more than once.

---

### security_team_review

> ⚠️ **C4 — VERDICT TABLE DISTINCTION**
> `security_team_review.final_verdict` stores the **analyst's final verdict**
> (`VERIFIED_MALICIOUS`, `VERIFIED_BENIGN`, `REJECTED`). It must never receive
> `BENIGN` or `SUSPICIOUS` — those are AI-only values on `secbret_analysis.verdict`.

```sql
CREATE TABLE security_team_review (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_report_id          UUID        UNIQUE NOT NULL REFERENCES user_report(id) ON DELETE CASCADE,
    secbret_analysis_id     UUID        NOT NULL REFERENCES secbret_analysis(id) ON DELETE CASCADE,
    reviewed_by             UUID        REFERENCES secbret_user(id) ON DELETE SET NULL,
    status                  VARCHAR(20) NOT NULL,
    reviewer_notes          TEXT,
    final_verdict           VARCHAR(30) NOT NULL,
    created_at              TIMESTAMP   NOT NULL DEFAULT NOW(),
    reviewed_at             TIMESTAMP,

    CONSTRAINT chk_review_status CHECK (status IN ('APPROVED', 'REJECTED', 'MODIFIED')),
    CONSTRAINT chk_review_verdict CHECK (final_verdict IN ('VERIFIED_MALICIOUS', 'VERIFIED_BENIGN', 'REJECTED'))
);

CREATE INDEX idx_review_report ON security_team_review (user_report_id);
CREATE INDEX idx_review_reviewed_by ON security_team_review (reviewed_by);
CREATE INDEX idx_review_status ON security_team_review (status);
```

---

### report_job

```sql
CREATE TABLE report_job (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url_id          UUID        NOT NULL REFERENCES scanned_url(id) ON DELETE CASCADE,
    requested_by    UUID        REFERENCES secbret_user(id) ON DELETE SET NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    file_data       BYTEA,
    file_size_bytes BIGINT,
    error_message   TEXT,
    created_at      TIMESTAMP   NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMP,

    CONSTRAINT chk_report_job_status CHECK (status IN ('PENDING', 'GENERATING', 'COMPLETED', 'FAILED'))
);

CREATE INDEX idx_report_job_url ON report_job (url_id);
CREATE INDEX idx_report_job_requested_by ON report_job (requested_by);
CREATE UNIQUE INDEX uq_report_job_active_per_url
    ON report_job (url_id)
    WHERE status IN ('PENDING', 'GENERATING');
```

`file_data` holds the PDF bytes (~250 KB each), mapped as a lazy `@Lob` — see the JPA `@Lob` mapping note below and Part II for the v2 filesystem-offload path. `error_message` is populated when `status` becomes `FAILED`. The partial unique index `uq_report_job_active_per_url` mirrors `uq_scan_job_active_per_url`: at most one active (`PENDING`/`GENERATING`) job per URL. On the resulting constraint violation, `ReportGenerationService` returns the existing active job's ID rather than failing (idempotent path). V16 adds the composite `idx_report_job_status_created`.

---

### share_link

```sql
CREATE TABLE share_link (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_job_id       UUID        NOT NULL REFERENCES report_job(id) ON DELETE CASCADE,
    created_by          UUID        REFERENCES secbret_user(id) ON DELETE SET NULL,
    uuid_token          VARCHAR(36) NOT NULL UNIQUE,
    expires_at          TIMESTAMP  NOT NULL,
    is_revoked          BOOLEAN     NOT NULL DEFAULT FALSE,
    access_count        INTEGER     NOT NULL DEFAULT 0,
    created_at          TIMESTAMP   NOT NULL DEFAULT NOW(),
    last_accessed_at    TIMESTAMP
);

CREATE INDEX idx_share_link_expires ON share_link (expires_at);
CREATE INDEX idx_share_link_created_by ON share_link (created_by);
```

The `UNIQUE` on `uuid_token` already creates its B-tree index, so there's no separate index for it; V16 adds the composite `idx_share_link_active`. **`access_count` must be bumped with a SQL-level atomic update** (`SET access_count = access_count + 1, last_accessed_at = NOW() WHERE id = :id`) — never an ORM read-modify-write, which loses updates under concurrent readers.

---

## Flyway Migration Naming

```
db/migration/
├── V1__create_secbret_user.sql
├── V2__create_scanned_url.sql
├── V3__create_scan_job.sql
├── V4__create_scan_result.sql
├── V5__create_user_report.sql
├── V6__create_secbret_analysis.sql
├── V7__create_security_team_review.sql
├── V8__create_report_job.sql
├── V9__create_share_link.sql
├── V10__add_account_lockout_fields.sql
├── V11__create_password_reset_token.sql
├── V12__create_webhook_subscription.sql
├── V13__create_idempotency_key.sql
├── V14__add_soft_delete_and_version_columns.sql
├── V15__add_trigger_set_updated_at.sql
├── V16__add_composite_indexes.sql
├── V17__add_report_job_error_message_and_scan_job_superseded_by.sql
├── V18__create_audit_log.sql
├── V19__create_api_token.sql
└── V20__add_concurrency_and_gdpr_triggers.sql
```

The numbering tells its own history: `V1`–`V9` are one-table-per-file from the initial build, then everything from `V10` is a feature or fix landing on top of a live schema. That's why the later migrations lean on `IF NOT EXISTS` / `IF EXISTS` guards (§Open Question Resolutions #1) — they have to be safe against a base schema that already has some of what they touch.

> **Migration Note — applied migrations are immutable.** Once a `V*` file has run against any shared environment, never edit it; Flyway checksums it and will refuse to start if it changes. Corrections go in a new `V{n+1}`. The `V20` triggers are the current head; the two AI/concurrency fixes (`link_superseded_scan_job`, `tombstone_audit_before_delete`) landed there rather than being back-patched into `V3`/`V18` for exactly this reason.

---


### JPA `@Lob` LAZY Mapping for `report_job.file_data`

`@Lob(fetch = FetchType.LAZY)` in JPA with PostgreSQL requires Hibernate bytecode enhancement or `@LazyGroup` to avoid eager loading of the BLOB. Without enhancement, every `SELECT` on `report_job` loads the full `file_data` into memory.

```java
@Entity
@Table(name = "report_job")
public class ReportJob {
    @Lob
    @Basic(fetch = FetchType.LAZY)
    @LazyGroup("pdf_data")
    @Column(name = "file_data")
    private byte[] fileData;
}
```

`@LazyGroup` requires Hibernate bytecode enhancement. Without it, the alternative is to move `file_data` into a separate 1:1 table or a `@SecondaryTable` so the BLOB isn't loaded on every `report_job` select.
## Extended Schema (V11+)

The tables and columns in this section are added in later migrations. They address the soft-delete / optimistic-locking / new-capability gaps called out in the design review.

### updated_at Trigger (shared function, applied per-table)

A shared trigger **function** used by every table that carries an `updated_at` column — in the v1 schema that is exactly two tables: `scanned_url` and `secbret_user`. It is not universal: the remaining tables deliberately have no `updated_at` column and MUST NOT have this trigger attached. Removing the caller-side `set updated_at = NOW()` requires running this trigger exactly once per table.

```sql
CREATE OR REPLACE FUNCTION trg_set_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER set_scanned_url_updated_at BEFORE UPDATE ON scanned_url
    FOR EACH ROW EXECUTE FUNCTION trg_set_updated_at();
CREATE TRIGGER set_secbret_user_updated_at BEFORE UPDATE ON secbret_user
    FOR EACH ROW EXECUTE FUNCTION trg_set_updated_at();
```

### password_reset_token (V11)

Single-use tokens issued through the forgot-password flow. The plaintext token is sent in the email hyperlink; only its SHA-256 hash is stored.

```sql
CREATE TABLE password_reset_token (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES secbret_user(id) ON DELETE CASCADE,
    token_hash      VARCHAR(64) NOT NULL UNIQUE,
    expires_at      TIMESTAMP NOT NULL,
    used_at         TIMESTAMP,
    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_reset_expiry CHECK (expires_at > created_at)
);

CREATE INDEX idx_password_reset_user ON password_reset_token (user_id);
CREATE INDEX idx_password_reset_expires ON password_reset_token (expires_at);
```

### webhook_subscription (V12)

> **v2 pre-positioning:** This table is created in v1 so the v2 feature can be
> enabled with a zero-downtime schema promotion (no `ALTER TABLE` required). No
> application code references this table in v1.

Webhooks let external systems receive scan/report completion events instead of polling. `signing_secret_enc` holds the AES-GCM ciphertext of the secret used to HMAC-SHA256 the request body, so the receiver can verify the webhook originated from SecBret. `event_types` is an array such as `{"scan.completed","report.completed"}`, and `last_delivery_status` records the raw HTTP status of the last delivery attempt.

```sql
CREATE TABLE webhook_subscription (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id            UUID NOT NULL REFERENCES secbret_user(id) ON DELETE CASCADE,
    callback_url        VARCHAR(2048) NOT NULL,
    signing_secret_enc  VARCHAR(512)  NOT NULL,
    event_types         VARCHAR(50)[] NOT NULL,
    is_active           BOOLEAN       NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMP     NOT NULL DEFAULT NOW(),
    last_delivery_at    TIMESTAMP,
    last_delivery_status INTEGER,

    CONSTRAINT chk_event_types CHECK (array_length(event_types, 1) >= 1),
    CONSTRAINT chk_delivery_status CHECK (last_delivery_status IS NULL
        OR (last_delivery_status >= 100 AND last_delivery_status <= 599))
);

CREATE INDEX idx_webhook_subscription_owner ON webhook_subscription (owner_id);
CREATE INDEX idx_webhook_subscription_active ON webhook_subscription (is_active) WHERE is_active = TRUE;
```

### idempotency_key (V13)

Stores the body hash and captured response for replay-safe `POST /scan`, `POST /incident`, and `POST /report-jobs/{urlId}` calls (the same three endpoints listed in Part III §Idempotency-Key). Keys are scoped per-user-per-endpoint to avoid cross-tenant collisions.

```sql
CREATE TABLE idempotency_key (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES secbret_user(id) ON DELETE CASCADE,
    idem_key            VARCHAR(255) NOT NULL,
    endpoint            VARCHAR(100) NOT NULL,
    request_hash        VARCHAR(64)  NOT NULL,
    response_status     INTEGER,
    response_body       TEXT,
    expires_at          TIMESTAMP    NOT NULL,
    created_at          TIMESTAMP    NOT NULL DEFAULT NOW(),

    UNIQUE (user_id, endpoint, idem_key),
    CONSTRAINT chk_idem_response CHECK (response_status IS NULL
        OR response_status BETWEEN 200 AND 599)
);

CREATE INDEX idx_idempotency_expires ON idempotency_key (expires_at);
```

> **Note on `endpoint` column:** The value stores the path template (e.g.
> "POST /report-jobs"), NOT the resolved path (e.g. "POST /report-jobs/abc-123").
> This ensures the same idempotency key string can be reused independently for
> different URLs, which is the intended scoping.

### api_token (v2 pre-positioning)

> **v2 pre-positioning:** This table is created in v1 so the v2 feature can be
> enabled with a zero-downtime schema promotion. No application code references
> this table in v1.
>
> The `bearerAuth` security scheme in `openapi.yaml` is a placeholder for v2.
> No endpoints use it in v1, and there is no admin provisioning flow.

```sql
CREATE TABLE api_token (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES secbret_user(id) ON DELETE CASCADE,
    token_hash      VARCHAR(64) NOT NULL UNIQUE,
    label           VARCHAR(100),
    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    last_used_at    TIMESTAMP,
    expires_at      TIMESTAMP
);

CREATE INDEX idx_api_token_user ON api_token (user_id);
```

### Soft-delete and Optimistic-locking Columns (V14)

Adds columns required for JPA-level concerns called out in the design review. The `deleted_at` tombstones are kept off the operational query path by partial indexes (see the original table definitions for the partial-index statements).

```sql
ALTER TABLE user_report ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
ALTER TABLE user_report ADD COLUMN IF NOT EXISTS version BIGINT NOT NULL DEFAULT 0;
ALTER TABLE scan_job ADD COLUMN IF NOT EXISTS version BIGINT NOT NULL DEFAULT 0;
ALTER TABLE scanned_url ADD COLUMN deleted_at TIMESTAMP;

DROP INDEX IF EXISTS uq_scanned_url_normalized_hash;
CREATE UNIQUE INDEX uq_scanned_url_normalized_hash ON scanned_url (normalized_hash) WHERE deleted_at IS NULL;
```

The `DROP INDEX` / `CREATE UNIQUE INDEX` pair swaps the base hard-unique on `normalized_hash` for a partial version (`WHERE deleted_at IS NULL`) so soft-deleted URLs can be re-scanned without constraint violations. It uses `DROP INDEX` (not `DROP CONSTRAINT`) because these are standalone indexes, and it must run in V14 alongside the `deleted_at` column. Each affected entity (`UserReport`, `ScanJob`) gets a `@Version` field in its JPA mapping; concurrent `UPDATE WHERE version = ?` throws `OptimisticLockException` so the application can re-fetch and retry instead of silently overwriting a peer's review.

### Soft-Delete Query Convention

`scanned_url` and `user_report` have `deleted_at` columns (V14 soft-delete). Partial indexes (`WHERE deleted_at IS NULL`) are pre-positioned as future-ready placeholders. No v1 write path touches `deleted_at`.

> **C4 FIX — `@Where` removed from v1 entities.** The `deleted_at` columns and partial
> indexes are pre-positioned in the schema, but no v1 API endpoint writes `deleted_at`.
> `@Where(clause = "deleted_at IS NULL")` is intentionally omitted from v1 entities.
> Because nothing in v1 writes `deleted_at`, the annotation would be a no-op for
> operational code. The important consequence is: **partial indexes are performance
> guards only — they do not provide JPA-level filtering.** Without `@Where`, any row
> whose `deleted_at` is set (by a test fixture, migration rollback, or manual SQL prompt)
> will still appear in all JPA queries — **data leakage, not data loss**. This is the
> opposite of the risk that exists when `@Where` *is* present.
>
> **v2 path:** Use `@FilterDef` / `@Filter` instead of `@Where` so admin views can
> explicitly disable the filter to see tombstoned rows. See `Part II` §F
> (Deletion Policy Matrix) for the full entity-level strategy and `Part II` §16
> (Soft-Delete Enforcement) for the v2 migration path.

Admin queries that must see tombstoned rows use a native SQL query, or in v2, a `@FilterDef` / `@Filter` annotation that can be selectively disabled. RLS was considered but rejected: JPA/Hibernate support is fragile at the ORM level, and at ~10-100 scans/day a filter clause is sufficient without the operational complexity.

> **Why no `@Where` in v1?** At 10-100 scans/day a filter clause is pragmatic and
> sufficient — but only when it is actually filtering something. A filter that
> hides accidentally-tombstoned rows during development is more dangerous than
> no filter. See Part II §16 for the full rationale.

---

### Composite and JSONB Indexes (V16)

The composite indexes that back the hot dashboard queries are added in their own migration to keep each V file small and easy to review:

```sql
CREATE INDEX idx_user_report_pending_created
    ON user_report (status, created_at DESC)
    WHERE status = 'PENDING_REVIEW';

CREATE INDEX idx_scan_job_status_created       ON scan_job (status, created_at DESC);
CREATE INDEX idx_report_job_status_created     ON report_job (status, created_at DESC);

CREATE INDEX idx_user_report_reported_by_created
    ON user_report (reported_by, created_at DESC);

CREATE INDEX idx_scan_result_tier1_gin ON scan_result USING GIN (tier1_findings jsonb_path_ops);
CREATE INDEX idx_scan_result_tier2_gin ON scan_result USING GIN (tier2_findings jsonb_path_ops);
CREATE INDEX idx_scan_result_tier3_gin ON scan_result USING GIN (tier3_findings jsonb_path_ops);
CREATE INDEX idx_evidence_urls_gin     ON user_report  USING GIN (evidence_urls   jsonb_path_ops);

CREATE INDEX idx_share_link_active
    ON share_link (uuid_token, is_revoked, expires_at);

CREATE INDEX idx_scanned_url_live
    ON scanned_url (last_scanned_at DESC)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_user_report_live
    ON user_report (created_at DESC)
    WHERE deleted_at IS NULL;
```

These back specific hot paths: the pending-review dashboard (score-sorted), the operator job queues, the "my incident reports" listing, JSONB containment queries against scan findings (e.g. "find URLs with expired SSL"), and the active share-link lookup. `idx_share_link_active` is a plain composite rather than a partial index on purpose — a partial predicate on a volatile expression like `NOW()` is ineffective, since expired rows are never automatically removed from the index. The two `*_live` indexes stay partial because operational queries always filter `deleted_at IS NULL`.

---

### V17: scan_job.superseded_by constraint and verdict extension

> **Base DDL note:** `report_job.error_message` and `scan_job.superseded_by` are
> present in the V1 base DDL. V17 adds them only for databases that were created
> before these columns were folded into the base definition. The `IF NOT EXISTS`
> guard makes each statement a safe no-op on a fresh schema.
>
> `security_team_review.chk_review_status` and `user_report.chk_report_verdict`
> already match their target values in the base DDL, so those constraint rewrites
> are also no-ops here. They are retained for environments where an older
> base DDL (without REJECTED) was deployed.

```sql
ALTER TABLE report_job ADD COLUMN IF NOT EXISTS error_message TEXT;

ALTER TABLE scan_job ADD COLUMN IF NOT EXISTS
    superseded_by UUID REFERENCES scan_job(id) ON DELETE SET NULL;

ALTER TABLE security_team_review DROP CONSTRAINT IF EXISTS chk_review_status;
ALTER TABLE security_team_review ADD CONSTRAINT chk_review_status
    CHECK (status IN ('APPROVED', 'REJECTED', 'MODIFIED'));

ALTER TABLE user_report DROP CONSTRAINT IF EXISTS chk_report_verdict;
ALTER TABLE user_report ADD CONSTRAINT chk_report_verdict CHECK (
    verdict IS NULL
    OR (
        verdict IN ('VERIFIED_MALICIOUS', 'VERIFIED_BENIGN', 'REJECTED')
        AND verdict NOT IN ('BENIGN', 'SUSPICIOUS')
    )
);
```

The two `ADD COLUMN IF NOT EXISTS` statements re-declare columns already present in the base DDL, so they are no-ops on a fresh schema and only matter for databases created before those columns were folded into the base definitions. The two constraint rewrites strengthen `chk_review_status` (adds `REJECTED`) and `chk_report_verdict` (the C1 dual-layer allowlist + AI-only denylist); both already match on a base-DDL-aligned database and exist for older deployments.

---

### V18: audit_log and ML model_version

An immutable audit trail for security-sensitive actions. `actor_username` is a snapshot of the username, updated to `deleted_{uuid}` when the user is deleted (so the trail survives GDPR erasure — see §V20). `internal_error_details` stores implementation detail that is never exposed through the public API.

```sql
CREATE TABLE audit_log (
    id              UUID      PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id        UUID      REFERENCES secbret_user(id) ON DELETE SET NULL,
    actor_username  VARCHAR(50),
    action          VARCHAR(100) NOT NULL,
    target_type     VARCHAR(50),
    target_id       UUID,
    detail          JSONB,
    internal_error_details TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_log_actor   ON audit_log (actor_id);
CREATE INDEX idx_audit_log_actor_username ON audit_log (actor_username);
CREATE INDEX idx_audit_log_created ON audit_log (created_at DESC);
CREATE INDEX idx_audit_log_target  ON audit_log (target_type, target_id);
```

`secbret_analysis.model_version` was originally slated for this migration but is folded into the base `secbret_analysis` definition (V6). The standalone `ALTER TABLE secbret_analysis ADD COLUMN model_version VARCHAR(50)` is reference-only — do not run it where V6 already includes the column.

**Actions logged:**

| Action | Triggered by |
|--------|-------------|
| `REVIEW_APPROVED` | `POST /admin/reviews/{reportId}` with `APPROVE` |
| `REVIEW_REJECTED` | `POST /admin/reviews/{reportId}` with `REJECT` |
| `ROLE_CHANGED` | `PUT /admin/users/{userId}/role` |
| `USER_DISABLED` | `PUT /admin/users/{userId}/status` (enabled → false) |
| `USER_ENABLED` | `PUT /admin/users/{userId}/status` (false → enabled) |
| `ACCOUNT_DELETED` | `DELETE /auth/me` |

### ⚠ Historical Note (Superseded by V20)

V18 originally required `UserService.deleteAccount()` to perform the following inside a single `@Transactional` boundary:

1. `UPDATE audit_log SET actor_username = 'deleted_{uuid}' WHERE actor_id = :userId`
2. `DELETE FROM secbret_user WHERE id = :userId`

This implementation is retained for historical context only.

Current implementations **MUST** use the V20 `tombstone_audit_before_delete` trigger.

Application code **MUST NOT** perform the explicit tombstone UPDATE.

The V20 trigger executes before the `ON DELETE SET NULL` cascade, ensuring that `actor_username` is tombstoned while `actor_id` is still present. This guarantees correct behavior for all deletion paths, including API requests, admin tooling, manual SQL, and future batch jobs.

**Migration for existing deployments**

Remove the explicit:

```sql
UPDATE audit_log
SET actor_username = 'deleted_{uuid}'
WHERE actor_id = :userId;
```

from `UserService.deleteAccount()` after deploying V20.

Leaving the application-level UPDATE duplicates responsibility, increases maintenance cost, and obscures the trigger as the canonical implementation of audit-log tombstoning during user deletion.

**Original V18 rationale**

The original application-level implementation required the UPDATE to execute before the DELETE because `ON DELETE SET NULL` would otherwise nullify `actor_id`, preventing the UPDATE from locating the audit records. The V20 trigger preserves this ordering automatically at the database level.

---

### Admin seed (post-migration, application-level)

Idempotent first-user bootstrap via `UserService.seedAdminIfEmpty()` at application startup using the `SEED_ADMIN_*` env vars. Not a Flyway migration — the application checks `SELECT COUNT(*) FROM secbret_user` and inserts only when the table is empty. Remove env vars from `.env` after first login.

The SQL below is an optional manual safety-net for environments where Flyway runs standalone without the application startup guard. The application BCrypt-hashes the raw `SEED_ADMIN_PASSWORD` before inserting, so the `:SEED_ADMIN_BCRYPT_HASH` placeholder expects the already-computed hash.

```sql
INSERT INTO secbret_user (id, username, email, password_hash, role, enabled)
SELECT gen_random_uuid(),
       :SEED_ADMIN_USERNAME,
       :SEED_ADMIN_EMAIL,
       :SEED_ADMIN_BCRYPT_HASH,
       'ADMIN',
       true
WHERE NOT EXISTS (SELECT 1 FROM secbret_user);
```

---

## Application-Level Stale Job Recovery

SecBret does not use a cron scheduler, but the application must handle the case where the JVM or host crashes while `scan_job` or `report_job` rows are in non-terminal states. A CDI startup observer runs on every Payara start, marking interrupted scan and report jobs `FAILED` and clearing expired idempotency keys — the last step matters so a replayed in-flight request can't return a cached `202` pointing at a now-`FAILED` job:

```sql
UPDATE scan_job
SET status = 'FAILED',
    error_message = COALESCE(error_message, '') || '; server restart'
WHERE status IN ('PENDING', 'RUNNING');

UPDATE report_job
SET status = 'FAILED',
    error_message = COALESCE(error_message, '') || '; server restart'
WHERE status IN ('PENDING', 'GENERATING');

DELETE FROM idempotency_key WHERE expires_at < NOW();
```

> **Caution:** In a multi-instance deployment (not planned for v1), a
coordination lock would be required. For the single-instance Payara deployment, the application startup hook is sufficient.

## ON DELETE Cascade Policy

The cascade chains are deliberate. Reference them here when reviewing schema migrations — the contract is "delete the URL, take everything that depends on it with you; users are protected by RESTRICT."

| Parent table | Child table | ON DELETE | Why |
|--------------|-------------|-----------|-----|
| `secbret_user` | `scan_job`, `user_report`, `report_job`, `share_link`, `security_team_review` | `SET NULL` | GDPR: hard DELETE on `secbret_user` fires these constraints; user-data FKs become NULL so the data survives but references are anonymized |
| `secbret_user` | `password_reset_token`, `idempotency_key`, `webhook_subscription`, `api_token` | `CASCADE` | Personal-data cleanup on account deletion; no audit requirement |
| `secbret_user` | `audit_log` (actor_id) | `SET NULL` | Audit records survive account deletion; actor_id becomes NULL; `actor_username` string retains `deleted_{uuid}` tombstone. **C3 FIX — DDL-enforced via V20 trigger `tombstone_audit_before_delete` (BEFORE DELETE on `secbret_user`):** The trigger fires before the DELETE and before the `ON DELETE SET NULL` cascade, writing `actor_username = 'deleted_{uuid}'` while `actor_id` is still set. This makes the tombstone ordering unconditional — it fires for all deletion paths including manual SQL, admin tooling, and future bulk-delete jobs, not just `UserService.deleteAccount()`. `UserService.deleteAccount()` **MUST NOT** contain an explicit tombstone UPDATE. The V20 trigger `tombstone_audit_before_delete` is the canonical implementation of audit-log tombstoning during user deletion. See the V18 Historical Note for the original implementation and the V20 section for the trigger definition. |
| `scan_job` | `scan_job` (superseded_by) | `SET NULL` | Preserves history when the superseding job is deleted |
| `scanned_url` | `scan_job`, `scan_result`, `user_report`, `report_job`, `secbret_analysis` | `CASCADE` | URL gone means everything tied to it goes |
| `scan_job` | `scan_result` | `CASCADE` | Job & result are 1:1; result has no meaning without job |
| `scan_result` | `secbret_analysis` | `SET NULL` | Analysis can survive without scan evidence (preserved for audit trail) |
| `user_report` | `secbret_analysis` | `SET NULL` | Analysis can exist standalone |
| `user_report` | `security_team_review` | `CASCADE` | Review is tied to report lifecycle |
| `report_job` | `share_link` | `CASCADE` | Sharable artifact removed when its source job is purged |

---

## Schema Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        secbret_user                                  │
│  PK: id (UUID)                                                       │
│  UQ: username, email                                                  │
│  IDX: role, locked_until                                              │
└───────────┬──────────────────────────────────────────────────────────┘
            │
            │ 1:N (submitted_by, reported_by, requested_by, reviewed_by, created_by)
            │
┌───────────▼─────────────────────────────────────────────────────────┐
│                        scanned_url                                   │
│  PK: id (UUID)                                                       │
│  UQ: url*, normalized_hash*  (*partial: WHERE deleted_at IS NULL)  │
│  IDX: community_verdict, last_scanned_at                             │
└─────┬───────────┬────────────────┬──────────────┬────────────────────┘
      │           │                │              │
  1:N │       1:N │            1:N │          1:N │
      │           │                │              │
┌─────▼─────┐ ┌──▼──────────┐ ┌───▼──────────┐ ┌─▼──────────────┐
│ scan_job  │ │ scan_result │ │ user_report  │ │ report_job     │
│ PK: id    │ │ PK: id      │ │ PK: id       │ │ PK: id         │
│ FK: url_id│ │ FK: url_id  │ │ FK: url_id   │ │ FK: url_id     │
│ FK: sub_by│ │ FK: job_id  │ │ FK: rep_by   │ │ FK: req_by     │
│ FK: super │ │ UQ: job_id  │ │              │ │ err_msg: TEXT  │
│ UQ: -     │ │             │ │              │ │                │
└─────┬─────┘ └─────────────┘ └──────┬───────┘ └───────┬────────┘
      │ 1:1                      1:1  │                 │ 1:1
      │                               │                 │
      └─────────────┐    ┌────────────┘          ┌─────┘
                    │    │                       │
              ┌─────▼────▼─────┐          ┌──────▼──────┐
              │ secbret_       │          │ share_link  │
              │ analysis       │          │ PK: id      │
              │ PK: id         │          │ FK: job_id  │
              │ FK: url_id     │          │ FK: by      │
              │ FK: result_id  │          │ UQ: token   │
              │ FK: report_id  │          │             │
              └───────┬────────┘          └─────────────┘
                      │ 1:1
                      │
              ┌───────▼────────────┐
              │ security_team_     │
              │ review             │
              │ PK: id             │
              │ FK: report_id     │
              │ FK: analysis_id   │
              │ FK: reviewed_by   │
              └────────────────────┘
```

---

## Query Patterns (Common Operations)

### Get pending reviews for analyst dashboard
```sql
SELECT ur.id, su.url, sa.threat_score, sa.verdict,
       COALESCE(u.username, '(anonymized)') AS reporter, ur.created_at
FROM user_report ur
JOIN scanned_url su ON ur.url_id = su.id
LEFT JOIN secbret_user u ON ur.reported_by = u.id
JOIN secbret_analysis sa ON sa.user_report_id = ur.id
LEFT JOIN security_team_review str ON str.user_report_id = ur.id
WHERE ur.status = 'PENDING_REVIEW'
  AND str.id IS NULL
ORDER BY sa.threat_score DESC, ur.created_at ASC;
```

### Get latest consolidated view for a URL
```sql
SELECT su.*, sr.*, sa.*, str.*
FROM scanned_url su
LEFT JOIN LATERAL (
    SELECT * FROM scan_result WHERE url_id = su.id
    ORDER BY created_at DESC LIMIT 1
) sr ON TRUE
LEFT JOIN LATERAL (
    SELECT * FROM secbret_analysis WHERE url_id = su.id
    ORDER BY created_at DESC LIMIT 1
) sa ON TRUE
LEFT JOIN LATERAL (
    SELECT str.* FROM security_team_review str
    JOIN user_report ur ON str.user_report_id = ur.id
    WHERE ur.url_id = su.id
    ORDER BY str.reviewed_at DESC LIMIT 1
) str ON TRUE
WHERE su.id = ?;
```

### Check share link validity
```sql
SELECT sl.id, sl.report_job_id, sl.uuid_token, sl.expires_at, sl.is_revoked,
       sl.access_count, sl.created_at, sl.last_accessed_at,
       rj.file_size_bytes
FROM share_link sl
JOIN report_job rj ON sl.report_job_id = rj.id
WHERE sl.uuid_token = ?
  AND sl.is_revoked = FALSE
  AND sl.expires_at > NOW();
```

---

---

### V20: DB-enforced concurrency and GDPR triggers

> **V20 note:** These triggers formalise two guarantees that were previously enforced
> only in application code, making them robust to future deletion paths, scripts, and
> admin tooling.

The first trigger (**C2**) links `superseded_by` via `AFTER INSERT` on a new `PENDING` `scan_job`, so the back-pointer is written atomically with the INSERT regardless of application code — `ScanPersistence.createJob()` must not write it (the row-level `FOR UPDATE` lock from the create path guarantees at most one unlinked `SUPERSEDED` job to match). The second (**C3**) tombstones `audit_log.actor_username` via `BEFORE DELETE` on `secbret_user`, so the username is stamped while `actor_id` is still populated, ahead of the `ON DELETE SET NULL` cascade; it is idempotent (a no-op when the user has no audit rows) and is the canonical owner of tombstoning — application code must not duplicate it. `BEFORE DELETE` trigger functions must `RETURN OLD`.

```sql
CREATE OR REPLACE FUNCTION trg_link_superseded_scan_job()
RETURNS trigger AS $$
BEGIN
    UPDATE scan_job
    SET    superseded_by = NEW.id
    WHERE  url_id        = NEW.url_id
      AND  status        = 'SUPERSEDED'
      AND  superseded_by IS NULL
      AND  id           <> NEW.id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER link_superseded_scan_job
    AFTER INSERT ON scan_job
    FOR EACH ROW
    WHEN (NEW.status = 'PENDING')
    EXECUTE FUNCTION trg_link_superseded_scan_job();


CREATE OR REPLACE FUNCTION trg_tombstone_audit_before_user_delete()
RETURNS trigger AS $$
BEGIN
    UPDATE audit_log
    SET    actor_username = 'deleted_' || OLD.id::text
    WHERE  actor_id = OLD.id;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER tombstone_audit_before_delete
    BEFORE DELETE ON secbret_user
    FOR EACH ROW
    EXECUTE FUNCTION trg_tombstone_audit_before_user_delete();
```

---

## Native Query Callsite Inventory

The following JPA repository methods use `@Query(nativeQuery = true)` (or `EntityManager.createNativeQuery`). Any schema rename or column addition must be reflected here.

| Repository | Method | Tables touched | Reason native |
|-----------|--------|---------------|--------------|
| `ScannedUrlRepository` | `findLatestConsolidatedView(UUID urlId)` | `scanned_url`, `scan_result`, `secbret_analysis`, `security_team_review`, `user_report` | `LATERAL` join not supported by JPQL |
| `ScanResultRepository` | `findTierSummaryByUrlId(UUID urlId)` | `scan_result` | `jsonb_each_text` JSONB operator not expressible in JPQL |
| `AuditLogRepository` | `findByActorIdOrderByCreatedAtDesc(UUID actorId, Pageable p)` | `audit_log` | Native query ordering by `created_at DESC`; the `actor_id` equality filter uses a partial index |
| `ReportJobRepository` | `findActiveSiblingJob(UUID urlId)` | `report_job` | Partial-index WHERE clause (`status IN ('PENDING','GENERATING')`) for concurrency guard; JPQL cannot target partial indexes |
| `UserRepository` | `findUsersWithExpiredLocks(Instant now)` | `secbret_user` | Uses `locked_until < :now` with a partial index; preferred over JPQL to allow PostgreSQL to use `idx_user_locked` |
| `ShareLinkRepository` | `findValidByToken(String token)` | `share_link`, `report_job` | Multi-predicate validity check (`is_revoked = FALSE AND expires_at > NOW()`) with JOIN; JPQL equivalent would load revoked rows into memory |

> **Maintenance note:** When adding a new native query, add a row to this table and tag the repository
> method with `// NATIVE — see Part IV §Native Query Callsite Inventory`.
> This prevents silent breakage when Flyway migrations rename columns or add NOT NULL constraints.


---

# Part V — Frontend UX, Accessibility & Cross-Platform

Canonical source for **Error Handling & UI/UX**, **Accessibility**, and **Cross-Platform Compatibility** (see `Part II` §A.1 Canonical Ownership).

WCAG 2.2 AA is a hard conformance target intended to survive an audit, so the RFC-2119 language here is load-bearing rather than stylistic — where a line says MUST, an auditor will check it. Section 1 (error handling) is the exception: it is design guidance rather than pass/fail criteria, much of it driven by HTMX's quirks — it does not swap content on non-2xx responses, and it needs explicit focus management after swaps.

## Normative Conventions

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are interpreted as in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119), consistent with `Part II` §A.

**Scope.** This document governs the server-rendered web UI: **Jakarta MVC (Krazo) + JSP + HTMX + Bootstrap 5**. The backend error contract is defined in `Part II` §9 (Error Handling Strategy) and §E (Error Response Standard).

**Baseline dependency.** **HTMX requires JavaScript** for partial updates and polling. All full-page navigation, forms, and content MUST function as standard HTML `GET`/`POST` round-trips; HTMX is an enhancement layer over that baseline (§3.6).

---

# 1. Error Handling & UI/UX

## 1.1 HTTP Status → UI Treatment Matrix

Every error surfaced to the user derives from the standard error envelope (`Part II` §E). The UI MUST map status codes to the following treatments:

| Status | Meaning | UI treatment |
|--------|---------|--------------|
| **400** Validation | Field-level errors (`errors[]`) | Re-render the form fragment with inline messages bound to each field (§1.5). No page reload. |
| **400** Malformed | Single `message`, no `errors[]` | Non-field form-level alert at the top of the form (`role="alert"`). |
| **401** Unauthenticated | Session expired / not logged in | Full-page redirect to `/login?next={path}`; on an HTMX request, server sends `HX-Redirect: /login` (§1.4). |
| **403** Forbidden | Authenticated, role/ownership denied | Inline forbidden notice or toast; the disallowed control SHOULD NOT have been rendered in the first place (defense in depth). |
| **404** Not found / hidden | Resource absent or not owner | Dedicated "Not found" view for full pages; toast for inline actions. Never reveal whether the resource exists (`Part II` §A.2). |
| **409** Conflict | e.g. admin disabling own account, unique-constraint | Toast with the server `message`; leave form state intact for correction. |
| **429** Rate limited | Bucket exhausted | Dismiss-blocking banner showing a **live countdown** derived from `Retry-After`; disable the triggering control until reset (§1.2). |
| **500** Server error | Unhandled | Generic error region that **displays the `correlationId`** verbatim with copy-to-clipboard, so users can quote it to support. Never render stack traces. |
| **503** Unavailable | DB/dependency down | Full-page maintenance view; polling elements stop and show a retry affordance. |
| **Network / timeout** | No response received | Client-side handler (§1.4) shows an "unable to reach server — retry" toast; no silent failure. |

## 1.2 Loading States

State-changing and long-running interactions MUST give visible progress feedback within **100 ms** of activation.

- **Request indicators.** Every HTMX-triggered element MUST use `hx-indicator` pointing at a spinner whose visibility is toggled by HTMX's `.htmx-request` class. The spinner element carries `role="status"` and visually-hidden text ("Loading…").
- **Button self-disabling.** Submit buttons MUST set `hx-disabled-elt="this"` (or equivalent) to prevent double-submission; the button label switches to a busy state.
- **Async job polling.** Scan and report status regions poll via `hx-trigger="every 3s"` (`Part II` §3). While `PENDING`/`RUNNING`/`GENERATING`, the region shows a determinate or indeterminate progress affordance and sets `aria-busy="true"` (§2.5). The server signals completion with `HX-Trigger: stopPolling` plus `HX-Refresh: true`; the page reloads to render the terminal state server-side (the global secbret.js listener also stops the poll).
- **Skeletons.** List/table surfaces (review queue, user table, dashboard) SHOULD render a lightweight skeleton or "Loading…" placeholder on first paint rather than an empty box.

## 1.3 User Feedback (Toasts & Confirmations)

- **Toasts.** Transient success/info/error notifications render into a single global toast region. Success/info use `aria-live="polite"`; errors use `aria-live="assertive"` (§2.5). Toasts MUST NOT be the *only* channel for critical errors that require user action — those also update the relevant inline region.
- **Server-driven toasts.** Services MAY emit `HX-Trigger: {"showToast": {...}}` so the server controls the message; the client listener renders it. Payload includes `level` and `message`.
- **Destructive-action confirmation.** The following MUST require an explicit confirmation step (modal dialog, §2.11) before the request is sent: **delete account** (`DELETE /auth/me`), **revoke share link** (`DELETE /api/v1/share/{uuid}`), and **reject incident** (`POST /admin/reviews/{reportId}` with `REJECT`). The confirmation modal restates the consequence and requires a deliberate second action.

## 1.4 Client-Side Exception Handling

Because HTMX **does not swap content on non-2xx responses by default**, the application MUST register global handlers (in `static/js/errors.js`) so no error is silently dropped — the `htmx:responseError` handler parses the standard error envelope (§E) and surfaces it:

```javascript
document.body.addEventListener('htmx:responseError', (e) => {
  const xhr = e.detail.xhr;
  showErrorFromEnvelope(xhr.status, safeParse(xhr.responseText));
});
document.body.addEventListener('htmx:sendError', () =>
  showToast('error', 'Unable to reach the server. Check your connection and retry.'));
document.body.addEventListener('htmx:timeout', () =>
  showToast('error', 'The request timed out. Please retry.'));
```

- The default request timeout MUST be set (`htmx.config.timeout`) so hung requests surface a `htmx:timeout` rather than spinning forever.
- Servers MAY use `HX-Retarget` / `HX-Reswap` to route an error partial to the toast/inline region instead of the original target.
- A last-resort `window.onerror` handler logs unexpected client exceptions and shows a generic toast; it MUST NOT expose internal detail.

## 1.5 Form Error Rendering

- Field errors from `errors[]` render adjacent to their input, associated via `aria-describedby`, with the input marked `aria-invalid="true"` (§2.6).
- On a 400, the returned fragment re-renders **with the user's submitted values preserved** — never a blank form.
- A form with multiple errors MUST render an **error summary** at the top (`role="alert"`, focus moved to it — §2.4) linking to each offending field.
- For a 500 during submission, the form-level alert includes the `correlationId`.

## 1.6 Empty & Zero-Result States

Lists, tables, and search results MUST render an explicit empty state (e.g. "No pending reviews" / "No scans yet — submit your first URL") with a next-action affordance where relevant — never a bare empty container that reads as a rendering bug.

---

# 2. Accessibility

## 2.1 Conformance Target

The UI MUST conform to **WCAG 2.2 Level AA**. New WCAG 2.2 success criteria in scope include **2.4.11 Focus Not Obscured (Minimum)**, **2.5.8 Target Size (Minimum)**, and **3.3.7 Redundant Entry**.

## 2.2 Semantic Structure & Landmarks

- Each page uses one `<h1>` and a logical, non-skipping heading order.
- Landmark elements are mandatory: `<header>`, `<nav aria-label="…">`, `<main id="main">`, `<footer>`. Multiple navigations MUST have distinguishing `aria-label`s.
- A visible-on-focus **skip link** to `#main` MUST be the first focusable element.
- Bootstrap components MUST retain their documented ARIA roles/attributes.

## 2.3 Keyboard Operability

- All functionality MUST be operable by keyboard alone; **no keyboard traps** (except modals, which trap intentionally and release on close — §2.11).
- Tab order MUST follow reading/visual order.
- A visible focus indicator MUST be present and MUST NOT be obscured by sticky headers or toasts (WCAG 2.4.11). Do not remove focus outlines without an equivalent replacement.
- Custom interactive widgets built on non-semantic elements MUST add `role`, `tabindex="0"`, and key handlers; prefer native `<button>`/`<a>` first.

## 2.4 Focus Management (HTMX swaps & modals)

HTMX partial swaps can strand keyboard/screen-reader users because focus lives on an element that gets replaced. The UI MUST:

- After a swap that changes the user's context (approve/reject action, form re-render on error), move focus to the updated region or its heading/status message (`htmx:afterSwap` handler).
- On a validation error, move focus to the error summary (§1.5).
- For modals: trap focus within the dialog while open, and **return focus to the invoking control** on close.

## 2.5 Dynamic Content Announcements

- **Polling regions** (scan/report status) are `aria-live="polite"` and toggle `aria-busy` during in-flight requests, so status transitions (RUNNING → COMPLETED) are announced without a reload.
- **Toasts**: `polite` for success/info, `assertive` for errors (§1.3).
- Live regions MUST exist in the DOM before content is injected; do not create the live region and populate it in the same swap.

## 2.6 Forms Accessibility

- Every control has a programmatically-associated `<label for>`; related controls use `<fieldset>`/`<legend>`.
- Required fields use `required` + `aria-required="true"`, not an asterisk alone.
- Errors: `aria-invalid="true"` + `aria-describedby` pointing at the visible message (§1.5).
- Autocomplete tokens (`autocomplete="username"`, `"current-password"`, `"new-password"`, `"email"`) MUST be set to support password managers and reduce entry (WCAG 1.3.5 / 3.3.7).
- Instructions/error text MUST NOT rely on color alone.

## 2.7 Color & Contrast

- Text contrast ≥ **4.5:1** (normal) / **3:1** (large text ≥18.66px, or ≥14px bold).
- Non-text UI components and meaningful graphics (icons, the threat gauge, focus indicators) ≥ **3:1** (WCAG 1.4.11).
- **Not color alone (WCAG 1.4.1).** The threat/verdict signal MUST pair the green/yellow/red gauge with the text **verdict badge** (BENIGN / SUSPICIOUS / VERIFIED_MALICIOUS / VERIFIED_BENIGN) and, where space allows, an icon — so meaning survives for color-blind and monochrome users. This applies equally to the PDF report (`Part II` §8).

## 2.8 Non-Text Content

- Informative images/icons have meaningful `alt`/`aria-label`; purely decorative graphics use `alt=""` / `aria-hidden="true"`.
- The SecBret logo has descriptive `alt`.

## 2.9 Motion

- All spinners/transitions MUST honor `prefers-reduced-motion: reduce` (disable non-essential animation). Polling itself is content update, not motion, and continues.

## 2.10 Screen-Reader Support Matrix

Core flows MUST be verified against at least:

| Screen reader | Browser | Platform |
|---------------|---------|----------|
| NVDA | Firefox | Windows |
| JAWS | Chrome | Windows |
| VoiceOver | Safari | macOS / iOS |

Core flows: login/register, submit scan + watch status, review queue approve/reject, PDF generate + share, account deletion confirmation.

## 2.11 Component Patterns

| Component | Requirements |
|-----------|-------------|
| **Data tables** (review queue, users) | `<table>` with `<th scope>`; sortable headers expose `aria-sort`; pagination is a labeled `<nav aria-label="Pagination">`; row actions are real `<button>`s. |
| **Pagination (HTMX)** | Current page marked `aria-current="page"`; focus moves into the refreshed list region after swap. |
| **Modal dialog** | `role="dialog"` + `aria-modal="true"` + `aria-labelledby`; focus trap; `Esc` closes; focus returns to trigger. |
| **Toasts** | Live region as in §2.5; dismiss button is keyboard-reachable and labeled. |
| **Polling status** | `aria-live="polite"`, `aria-busy` toggling; terminal state announced. |

## 2.12 PDF Accessibility

OpenPDF has limited tagged-PDF (PDF/UA) support. The generated report (`Part II` §8) MUST at minimum set the document title and language, and MUST NOT encode the verdict by color alone (the badge text carries the verdict — §2.7). Full PDF/UA tagging is a tracked v2 enhancement.

## 2.13 Accessibility Acceptance Criteria

A surface is accessibility-complete when:

- [ ] `axe`/equivalent automated scan reports zero critical/serious violations.
- [ ] The flow is fully operable keyboard-only with a visible, unobscured focus indicator.
- [ ] Dynamic updates (polling, toasts, form errors) are announced by a screen reader.
- [ ] All form controls are labeled; errors are associated and not color-only.
- [ ] Contrast checks pass at AA for text and UI components.

---

# 3. Cross-Platform Compatibility

## 3.1 Responsive Strategy

The UI is **mobile-first** on Bootstrap 5's 12-column grid. Layouts stack on small viewports and expand at larger breakpoints; content containers MUST use grid columns and relative units, never fixed pixel widths.

## 3.2 Viewport

Every page MUST include:

```html
<meta name="viewport" content="width=device-width, initial-scale=1">
```

User scaling MUST NOT be disabled (no `maximum-scale=1` / `user-scalable=no`) — WCAG 1.4.4.

## 3.3 Bootstrap Breakpoints

| Breakpoint | Min width | Primary target |
|------------|-----------|----------------|
| `xs` | <576px | Small phones |
| `sm` | ≥576px | Large phones |
| `md` | ≥768px | Tablets |
| `lg` | ≥992px | Laptops |
| `xl` | ≥1200px | Desktops |
| `xxl` | ≥1400px | Large desktops |

## 3.4 Per-Surface Adaptation

| Surface | Small screen behavior |
|---------|----------------------|
| **Primary navigation** | Bootstrap navbar collapses to a hamburger `<button>` with `aria-expanded`/`aria-controls`. |
| **Dashboard cards** | Reflow from multi-column to single column. |
| **Data tables** (review queue, users) | Wrapped in `.table-responsive` for horizontal scroll; avoid clipping critical columns. |
| **Forms** | Full-width inputs; labels above fields; no horizontal scrolling of the form. |
| **PDF/share actions** | Buttons remain reachable and ≥ target size (§3.5) on touch. |

## 3.5 Touch Targets & Input Modality

- Interactive targets MUST meet **WCAG 2.5.8 (AA): ≥24×24 CSS px** with adequate spacing.
- Touch-primary surfaces SHOULD provide **≥44×44 CSS px** targets (iOS HIG / WCAG 2.5.5 AAA guidance) for comfort.
- The UI MUST support mouse, touch, and keyboard without hover-only interactions hiding essential content or actions (WCAG 1.4.13).

## 3.6 Progressive Enhancement / No-JS Baseline

HTMX enhances the app but is not a hard dependency for core reachability:

- Full-page navigation, forms (`POST`), and content MUST work as standard HTML round-trips.
- With JS disabled, polling and inline partials degrade to manual full-page refresh; the app MUST remain usable (submit scan, view result on reload), not blank.
- CSRF tokens are present in server-rendered forms regardless of HTMX (`Part II` §5).

## 3.7 Browser Support Matrix

| Browser | Supported versions |
|---------|--------------------|
| Chrome / Chromium | Last 2 stable |
| Firefox | Last 2 stable + current ESR |
| Safari (macOS / iOS) | Last 2 stable |
| Edge (Chromium) | Last 2 stable |

Legacy Internet Explorer is **not supported**; HTMX and Bootstrap 5 target evergreen browsers.

## 3.8 Test Matrices

**Viewport / device matrix** — verify no horizontal overflow, no clipped controls, working touch interactions at:

`320` · `375` · `768` · `1024` · `1440` · `1920` px

**Cross-browser smoke test** — for each supported browser (§3.7), verify: form submission, HTMX polling/swaps, toast rendering, modal open/close, and PDF download.

## 3.9 Test Automation

- Drive the flows above with **Playwright** device emulation across the browser matrix; assert no overflow and that key controls are visible and hittable at each viewport.
- Real-device coverage (e.g. BrowserStack) SHOULD supplement emulation for Safari/iOS before a release.
- Accessibility automation (`axe`) runs in the same harness (§2.13).

---

## Cross-References

| Topic | Canonical / related source |
|-------|---------------------------|
| Error Response envelope | `Part II` §E |
| Backend error-handling strategy | `Part II` §9 |
| Authorization status semantics (401/403/404) | `Part II` §A.2 |
| HTMX interaction patterns | `Part II` §3 |
| Security headers / CSP / CSRF | `Part II` §5 |
| Verdict enums & badges | `Part III` §9 |
| PDF report layout | `Part II` §8 |
