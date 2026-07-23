# SecBret

> A self-hosted phishing/URL analysis and incident-reporting platform built on Jakarta EE 10.
> Users submit URLs for automated multi-tier scanning, an AI engine (Java rules + Python ML
> sidecar) scores the threat, a security team verifies uncertain cases, and verdicts feed a
> public community dashboard and shareable PDF reports.

![Jakarta EE](https://img.shields.io/badge/Jakarta%20EE-10-blue)
![Payara](https://img.shields.io/badge/Payara-6-orange)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-14%2B-336791)
![Python ML](https://img.shields.io/badge/ML%20sidecar-Python%203.11%20%2F%20gRPC-3776AB)
![Docker Compose](https://img.shields.io/badge/deploy-Docker%20Compose-2496ED)
![License: MIT](https://img.shields.io/badge/License-MIT-green)

---

## Table of Contents

1. [Project Description](#1-project-description)
2. [Project Members](#2-project-members)
3. [Architecture](#3-architecture)
4. [Source Code Organization](#4-source-code-organization)
5. [Error Handling & UX](#5-error-handling--ux)
6. [Data Validation](#6-data-validation)
7. [Security](#7-security)
8. [Cross-Platform Compatibility](#8-cross-platform-compatibility)
9. [Getting Started (Containerized Deployment)](#9-getting-started-containerized-deployment)
10. [Documentation](#10-documentation)
11. [License](#license)

---

## 1. Project Description

### Objectives

SecBret lets a small security team and its reporters triage potentially malicious URLs without manual investigation. Every submitted URL is scanned across up to three tiers, scored by a hybrid AI engine, and resolved automatically when the score is confident; uncertain cases are queued for human review. Verified verdicts are published to a community dashboard and can be exported as portable PDF reports.

### Context

The platform targets low scale (10–100 scans/day, ~5 req/s) and runs as a single Payara instance. Every design choice favors operational simplicity over premature scale-out: an in-process job queue, an in-memory rate limiter, and PDF storage as a database BLOB. Horizontal-scaling concerns (shared session store, distributed rate limiting) are explicitly deferred to v2 and tracked as Known Gaps.

### Main Features

| Feature | Description |
|---------|-------------|
| **Multi-tier URL scanning** | Quick (Tier 1) or Deep (Tiers 1–3) scans: domain/SSL/headers, HTML/forms/scripts, phishing-kit & CVE detection. Async with HTMX status polling. |
| **Hybrid AI threat scoring** | Java rules engine runs synchronously; when the score is uncertain (0.05–0.95) a Python ML sidecar is consulted over gRPC with a 2 s ceiling and circuit breaker. |
| **Incident reporting** | Users report suspected phishing; confident scores auto-resolve, uncertain ones enter a human review queue. |
| **Security-team review** | Analysts/admins approve, reject, or modify verdicts, with full audit logging. |
| **PDF reports & share links** | 3-page condensed PDF (OpenPDF), distributable via time-limited, revocable UUID share links. |
| **Public community dashboard** | Anonymous lookup of established verdicts for known URLs. |
| **Account & access management** | Registration/login (Soteria), RBAC, GDPR account deletion, admin user management. |

### Technologies

- **Platform:** Jakarta EE 10 on Payara 6, with MVC (Krazo), JAX-RS, JPA/Hibernate 6, CDI, Bean Validation, Soteria security, Jakarta Concurrency.
- **Frontend:** Server-rendered JSP + HTMX + Bootstrap 5 (no SPA build step).
- **AI/ML:** Java rules engine + Python 3.11 ML sidecar (scikit-learn LogisticRegression trained on PhiUSIIL) over gRPC; see `ml-sidecar/README.md`.
- **Data:** PostgreSQL 14+, Flyway migrations (V1–V20).
- **Libraries:** jsoup (HTML parsing), OpenPDF (reports), Jakarta Mail (SMTP), SLF4J/Logback (structured JSON logs).
- **Testing:** JUnit 5 + Mockito (unit), Testcontainers + AssertJ (integration).
- **Delivery:** Maven, Docker & Docker Compose (Payara + PostgreSQL + ML sidecar + backup).

### Use Cases

- A reporter submits a suspicious URL, watches the live scan status, and reads the tiered findings.
- A reporter reports a phishing site and generates a shareable PDF for non-technical stakeholders.
- An analyst triages the pending-review queue and confirms or overturns an AI verdict.
- An admin manages user roles, enables/disables accounts, and unlocks locked users.
- Anyone checks the public dashboard to see whether a URL is community-verified as malicious or benign.

See `spec/SecBret_Usecases.png` for the full use-case diagram and `spec/SPECIFICATION.md` Part II §13 for user stories.

---

## 2. Project Members

| Name | Role | Responsibilities |
|------|------|------------------|
| EL khalfi Ossama | **Specs and Code** | Specification authoring; Jakarta EE core — JAX-RS resources, CDI services, JPA repositories, transaction boundaries; JSP/HTMX frontend |
| Taouimi Issam | **Test** | Unit tests (JUnit 5 + Mockito) and integration tests (Testcontainers); coverage; security/UX validation |
| Lyazidi Ali | **AI / ML Engineer** | Java rules engine, Python gRPC sidecar, model training & feature extraction |

---

## 3. Architecture

SecBret is a monolithic WAR deployed to a single Payara instance, backed by PostgreSQL, with a separately deployed Python ML sidecar. Communication with the sidecar is over gRPC.

```
Browser ──HTTP──▶ Payara (SecBret WAR)  ──JDBC──▶ PostgreSQL
                       │
                       └──gRPC──▶ Python ML Sidecar
```

Rendered diagrams live in `spec/`:

| Diagram | File |
|---------|------|
| C4 System Context | `spec/SecBret_C4_Context.png` |
| C4 Container | `spec/SecBret_C4_Container.png` |
| MVC layers | `spec/SecBret_MVC_Layers.png` |
| Deployment | `spec/SecBret_Deployment.png` |
| Data model (ERD) | `spec/SecBret_ERD.png` |
| Workflows | `spec/SecBret_*_Workflow.png` |

### Separation of Concerns (Front-end vs Back-end)

| Layer | Technology | Responsibility |
|-------|-----------|----------------|
| **Presentation (front-end)** | JSP + HTMX + Bootstrap 5, served by Jakarta MVC (Krazo `@Controller`) | Server-rendered pages and HTMX partials; no client-side business logic |
| **API (back-end)** | JAX-RS `@Path` resources returning JSON | REST contract for programmatic access (`/api/v1/*`), mirrored by the web layer |
| **Service** | CDI `@ApplicationScoped` beans | Business logic, transaction boundaries, orchestration |
| **Repository** | JPA interfaces (Hibernate 6) | Data access, native queries where needed |
| **Async** | Jakarta Concurrency `@ManagedExecutorService` | Scanning and PDF generation off the request thread |
| **ML** | Python sidecar (gRPC) | Isolated, independently deployable ML scoring |

The web layer (Krazo/JSP) and the API layer (JAX-RS) are distinct controllers over the same service layer; the browser UI and the REST API never share rendering concerns.

### Why these frameworks

| Choice | Justification |
|--------|---------------|
| **Jakarta EE 10 / Payara** | Single, self-contained enterprise platform (security, persistence, concurrency, DI) with no external framework sprawl; fits a single-instance deployment. |
| **JSP + HTMX + Bootstrap** (over a SPA) | Server-rendered simplicity with dynamic partials; no separate build toolchain, bundle budget, or hydration complexity for a low-scale internal tool. |
| **Java rules + Python ML sidecar** | Rules cover common patterns transparently and synchronously; ML handles edge cases in the language best suited to it, deployed and scaled independently. |
| **PostgreSQL + Flyway** | ACID strong consistency (reads-own-writes), mature SQL migrations with excellent Hibernate compatibility. |
| **PDF as DB BLOB** | Eliminates filesystem/volume path management and path-traversal defense; transactionally consistent at ~25 MB/month. |
| **Docker Compose** | One-command reproducible full-stack bring-up (Payara + PostgreSQL + sidecar + backup). |

---

## 4. Source Code Organization

Organized by feature/domain, not by file type. Full tree in `spec/SPECIFICATION.md` Part II §12.

```
SecBret/
├── src/main/java/com/secbret/
│   ├── config/       CDI producers, Payara config
│   ├── controller/   MVC (Krazo) + REST (JAX-RS) controllers
│   ├── service/      CDI service beans (business logic)
│   ├── scanner/      Tier 1/2/3 scan engines
│   ├── ai/           Rules engine + gRPC ML client
│   ├── report/       OpenPDF generation
│   ├── security/     Soteria IdentityStore, RBAC
│   ├── filter/       Rate limit, security headers, CORS, correlation ID
│   ├── model/        entity / dto / enums
│   └── repository/   JPA repositories
├── src/main/resources/db/migration/   Flyway V1–V20
├── src/main/webapp/WEB-INF/views/     JSP templates (+ HTMX)
├── src/test/java/com/secbret/         unit + integration (Testcontainers)
├── ml-sidecar/       Python gRPC service, model, proto
├── docker-compose.yml, Dockerfile, .env.example
└── spec/             design, API, DB, diagrams
```

**Conventions:** Java classes `PascalCase`, methods/fields `camelCase`, constants `UPPER_SNAKE_CASE`; DB tables/columns `snake_case`; Flyway scripts `V{n}__description.sql`; REST under `/api/v1`. Enumerations are centralized (`SPECIFICATION.md Part III` §9) and stable within v1.

**Testing:** Unit tests (JUnit 5 + Mockito) for services/scanners/controllers; integration tests (Testcontainers against real PostgreSQL) for repository and end-to-end DB behavior.

---

## 5. Error Handling & UX

> **Canonical specification:** [`spec/SPECIFICATION.md`](spec/SPECIFICATION.md) Part V §1 (full
> HTTP-status→UI mapping, loading/feedback states, and client-side HTMX exception handling).

- **Single error envelope** for all API errors: `status`, `error`, `message`, `timestamp`,
  `path`, `correlationId` (validation errors add a `errors[]` field list). Canonical:
  `SPECIFICATION.md Part II` §E.
- **Layered strategy** (`SPECIFICATION.md Part II` §9): Bean Validation → 400; custom exception
  hierarchy mapped to 404/403/401/409; a JAX-RS `ExceptionMapper<Throwable>` catch-all → 500.
- **Three-tier authorization semantics:** 401 (unauthenticated), 403 (authenticated but
  forbidden), 404 (hidden for ownership/privacy to prevent enumeration).
- **Loading & feedback (HTMX):** scan and report status use `hx-trigger="every 3s"` polling;
  the server sends `HX-Trigger: stopPolling` on terminal states; toasts surface success/error
  via `hx-on::after-request`.
- **Correlation IDs:** every request/response and error body carries `X-Correlation-Id` for
  support cross-referencing.

---

## 6. Data Validation

Validation is enforced at every boundary, front-end and back-end:

- **Bean Validation** on request DTOs (Hibernate Validator) → field-level 400 responses.
- **Front-end:** JSP forms use HTML5 constraints and inline error rendering bound to the API's
  `errors[]` field messages; HTMX re-renders the form fragment with messages on 400.
- **Business rules:** password policy (≥12 chars + HIBP breach check, `SPECIFICATION.md Part II` §B),
  URL normalization & dedup (§C), scanner input limits (max 2048-char URL, private-IP block).
- **Database constraints:** `CHECK` constraints, unique indexes (e.g. one active scan job per
  URL), and dual-layer verdict guards backstop application logic (`SPECIFICATION.md Part IV`).

---

## 7. Security

Defense-in-depth across web and API layers (`SPECIFICATION.md Part II` §5):

| Area | Control |
|------|---------|
| **Injection (SQLi)** | JPA parameterized queries; no string-concatenated SQL |
| **XSS** | Per-request nonce CSP; JSP output escaping; no inline scripts |
| **CSRF** | Krazo per-session token for JSP forms + `X-CSRF-Token` header for JAX-RS; `HttpOnly`/`SameSite=Strict` cookies (`Secure` off for the plain-HTTP local stack; re-enable behind TLS) |
| **API hardening** | HSTS, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, CORS whitelist |
| **AuthN/AuthZ** | Soteria + DB IdentityStore; `@RolesAllowed`; RBAC matrix (`SPECIFICATION.md Part II` §4) |
| **Password storage** | BCrypt cost 12; plaintext never stored; HIBP k-anonymity breach check |
| **Account protection** | Lockout after 5 failed logins (15 min); 30 min idle session timeout; session regeneration on login |
| **Scanner safety (SSRF)** | Private-IP block, redirect cap, response-size limit, no JS execution |
| **Rate limiting** | Per-user/per-IP token buckets with stampede protection and `429` + `Retry-After` |
| **Secrets** | Environment variables only; `.env` excluded from source; admin seed removed after first run |

---

## 8. Cross-Platform Compatibility

> **Canonical specification:** [`spec/SPECIFICATION.md`](spec/SPECIFICATION.md) Part V §3
> (responsive strategy, per-surface adaptation, touch targets, no-JS baseline, and full test matrices).

SecBret is a responsive, server-rendered web app. The UI is built mobile-first on
Bootstrap 5's 12-column grid; HTMX only swaps HTML fragments, so rendering is identical
across engines and there is no client-framework runtime to diverge between browsers.

### Responsive strategy

- **Viewport meta** on every page: `<meta name="viewport" content="width=device-width, initial-scale=1">`.
- **Mobile-first Bootstrap breakpoints**, so layouts stack on `xs/sm` and expand on `md+`:

  | Breakpoint | Min width | Target device |
  |------------|-----------|---------------|
  | `sm` | 576px | Large phones |
  | `md` | 768px | Tablets |
  | `lg` | 992px | Laptops |
  | `xl` | 1200px | Desktops |

- **Collapsing navigation:** Bootstrap navbar collapses to a hamburger toggle on small screens.
- **Fluid data tables:** review/user tables wrap in `.table-responsive` for horizontal scroll on narrow screens.
- **Touch targets:** interactive controls sized ≥44×44px per WCAG 2.5.8.
- **No fixed pixel widths** for content containers; use grid columns and relative units.

### Browser support matrix

| Browser | Supported versions |
|---------|--------------------|
| Chrome / Chromium | Last 2 stable |
| Firefox | Last 2 stable + current ESR |
| Safari (macOS/iOS) | Last 2 stable |
| Edge (Chromium) | Last 2 stable |

Legacy Internet Explorer is **not** supported. HTMX and Bootstrap 5 both target evergreen
browsers.

### Compatibility testing

- **Device matrix:** verify at 320 / 375 / 768 / 1024 / 1440 px; no horizontal overflow, no
  clipped controls, working touch interactions.
- **Cross-browser:** smoke-test each supported browser for form submission, HTMX polling/swaps,
  and PDF download.
- **Automation:** drive the flows above with Playwright device emulation (or BrowserStack for
  real-device coverage) as part of the QA pass.

---

## 9. Getting Started (Containerized Deployment)

**Prerequisites:** Docker 24+ and Docker Compose 2.x.

```bash
# 1. Configure environment
cp .env.example .env
#   edit .env: set DB_PASSWORD/POSTGRES_PASSWORD, SMTP_*, and the SEED_ADMIN_* values

# 2. Build and start the full stack (Payara + PostgreSQL + ML sidecar + backup)
docker compose up --build

# 3. Verify health
curl -sf http://localhost:8080/api/v1/health/ready

# 4. Open the app
#   http://localhost:8080/dashboard/public   (public)
#   log in with the SEED_ADMIN_* credentials, then remove those vars from .env
```

---

## 10. Documentation

**`spec/SPECIFICATION.md` is the single source of truth.**

| Topic | Canonical artifact & document |
|---|---|
| Requirements, security posture, AI scoring, failure modes | `spec/SPECIFICATION.md` |
| REST contract | `spec/openapi.yaml` (Part III is its prose rendering) |
| Database schema | Flyway migrations `src/main/resources/db/migration/` V1–V20 (Part IV describes them) |
| Runtime configuration | `.env.example` + `AppConfig` |
| Deployment | `docker-compose.yml` |
| CI security gates (Trivy, pip-audit) | `.github/workflows/ci.yml` |

Specification and implementation live side by side; every artifact above exists (build
complete, Milestone M6, 2026-07-16). The ML sidecar's model and training pipeline are
documented in `ml-sidecar/README.md` (deep dive: `docs/obsidian/SecBret ML Sidecar - Model &
Features Guide.md`).

#### Notes

- The stack is local/demo-scoped: plain HTTP on :8080, no TLS proxy. The session cookie now
  defaults to `Secure=true` in `web.xml` (H-2); the local HTTP demo keeps working via a
  `cookieSecure=false` override in `glassfish-web.xml`. 
- Dependency-CVE scanning runs in CI (Trivy + pip-audit).
---

## License

Released under the [MIT License](LICENSE). © 2026 .
