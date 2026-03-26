# Pre-Launch Security & Distribution Audit Report

**Project:** USGS Publications Warehouse MCP Server v0.2.0
**Date:** 2026-02-17
**Auditor:** Automated code review + manual analysis
**Scope:** Security (OWASP), packaging, distribution, runtime best practices

---

## Executive Summary

The USGS Publications Warehouse MCP Server is a **well-hardened, security-conscious** implementation. The codebase demonstrates deep awareness of MCP-specific security risks, OWASP LLM Top 10, and general web security best practices. The project is **close to production-ready** with a few issues that should be addressed before launch.

| Severity | Count | Status |
|----------|-------|--------|
| **CRITICAL** | 1 | HTML escaping bug breaks legitimate queries |
| **HIGH** | 2 | Missing .dockerignore, no pytest in dev deps |
| **MEDIUM** | 6 | Docker/CI/packaging improvements |
| **LOW** | 5 | Polish and documentation gaps |
| **INFO** | 8 | Best practices already implemented (commendations) |

---

## Part 1: MCP Packaging & Distribution Best Practices

### 1.1 Packaging (pyproject.toml)

| Check | Status | Notes |
|-------|--------|-------|
| Uses `pyproject.toml` (PEP 621) | PASS | Modern metadata format |
| Build backend (`hatchling`) | PASS | Well-supported, fast |
| Entry point script defined | PASS | `usgs-warehouse-mcp = "main:main"` |
| Wheel includes only needed files | PASS | `only-include = ["main.py", "security/"]` |
| Lock file present (`uv.lock`) | PASS | Reproducible installs |
| Python version pinned | PASS | `requires-python = ">=3.12"`, `.python-version = 3.12` |
| Dependencies version-pinned (lower bound) | PASS | `mcp[cli]>=1.2.0`, `httpx[http2]>=0.28.0` |

**Recommendation:** Consider adding upper bounds or using `~=` for dependencies to prevent unexpected breaking changes (e.g., `mcp[cli]>=1.2.0,<2`).

### 1.2 Distribution Channels

| Channel | Status | Notes |
|---------|--------|-------|
| Git clone + `uv sync` | PASS | Primary method, works well |
| `pip install -e .` | PASS | Editable install works |
| Docker image | PASS | Multi-stage build present |
| Kubernetes manifests | PASS | Full k8s stack with kustomize |
| PyPI publishing | READY | `uv build && uv publish` documented |
| Install script | PASS | `scripts/install.sh` present |

### 1.3 Running the Server

| Transport | Status | Notes |
|-----------|--------|-------|
| stdio (Claude Desktop, Cursor) | PASS | Default, zero-config |
| SSE (`GET /sse`, `POST /messages`) | PASS | Auth middleware applied |
| Streamable HTTP (`POST /mcp`) | PASS | Auth middleware applied |
| Health check (`GET /health`) | PASS | Skips auth, for LB/monitoring |
| CLI argument parsing | PASS | `--transport`, `--host`, `--port`, `--allowed-hosts` |
| Environment variable config | PASS | `MCP_TRANSPORT`, `MCP_HOST`, `MCP_PORT` |

---

## Part 2: Security Audit (OWASP & MCP-Specific)

### 2.1 OWASP Top 10 for LLM Applications (2025)

| Risk | Status | Implementation |
|------|--------|----------------|
| **LLM01: Prompt Injection** | PASS | Input validation with injection pattern detection (SQL, XSS, template, prototype pollution) |
| **LLM02: Insecure Output Handling** | PASS | HTML stripping in `_strip_html()`, no user input reflected raw |
| **LLM04: Model DoS** | PASS | Rate limiting (per-minute, per-hour, burst), circuit breaker, concurrent request limits |
| **LLM05: Supply Chain** | PASS | URL allowlisting, TLS 1.2+ enforcement, cert verification |
| **LLM06: Sensitive Disclosure** | PASS | Sensitive field redaction in logs, no PII in responses, generic error messages |
| **LLM07: Insecure Plugin Design** | PASS | Strict parameter validation, read-only tools only, OpenAI schema compatibility |
| **LLM08: Excessive Agency** | PASS | Single read-only tool, no write/execute/delete operations |

### 2.2 MCP-Specific Security Controls

| Control | Status | Implementation |
|---------|--------|----------------|
| Input validation & sanitization | PASS | `InputValidator` with length limits, character allowlists, injection detection |
| Rate limiting (token bucket) | PASS | Per-minute, per-hour, burst, concurrent, session-level limits |
| Circuit breaker pattern | PASS | Opens after 5 failures, 60s recovery, half-open testing |
| Audit logging (SIEM-ready) | PASS | Structured JSON, dual timestamps, correlation IDs, request IDs |
| TLS enforcement | PASS | TLS 1.2+, cert verification, HTTP/2 |
| URL allowlisting | PASS | Only `https://pubs.usgs.gov/pubs-services` allowed |
| DNS rebinding protection | PASS | Configurable via MCP SDK's `TransportSecuritySettings` |
| HTTP security headers | PASS | X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy |
| Authentication (HTTP transports) | PASS | API key (SHA-256 hash + constant-time comparison) + Bearer token (384-bit entropy) |
| Brute force protection | PASS | Per-IP failure tracking, lockout after threshold |
| Token rotation | PASS | Grace period support for zero-downtime rotation |
| Distributed tracing | PASS | W3C Trace Context compatible, OpenTelemetry format |
| Context size limits | PASS | Request/response size caps, field truncation |
| Sensitive field redaction | PASS | Automatic redaction in audit logs |
| Privacy controls | PASS | No author emails exposed, PII excluded |

### 2.3 Authentication & Authorization

| Check | Status | Notes |
|-------|--------|-------|
| API key generation (256-bit entropy) | PASS | `secrets.token_urlsafe(32)` |
| Bearer token generation (384-bit) | PASS | `secrets.token_urlsafe(48)` with `usgs_` prefix |
| Constant-time comparison | PASS | `hmac.compare_digest()` used for both |
| Hash-only storage | PASS | SHA-256 hash stored, plaintext discarded after display |
| Brute force lockout (API key) | PASS | 10 failures in 5 min triggers lockout |
| Brute force lockout (Bearer) | PASS | Configurable threshold, per-source tracking |
| Token format validation | PASS | Regex validation before expensive comparison |
| Auth bypass for health checks | PASS | Only `/health` skips auth |
| Security headers on all responses | PASS | Including error responses |
| Static credential support (.env) | PASS | Persistent credentials across restarts |

### 2.4 Container Security (Docker)

| Check | Status | Notes |
|-------|--------|-------|
| Multi-stage build | PASS | Builder + production stages |
| Non-root user | PASS | `mcpuser` created and used |
| No unnecessary packages | PASS | `python:3.12-slim` base |
| Health check | PASS | In both Dockerfile and docker-compose |
| Resource limits | PASS | CPU/memory limits in docker-compose |
| Read-only filesystem | PASS | `read_only: true` in docker-compose |
| No new privileges | PASS | `no-new-privileges:true` |
| tmpfs for `/tmp` | PASS | Writable temp space without persistence |

### 2.5 Kubernetes Security

| Check | Status | Notes |
|-------|--------|-------|
| Non-root user (pod level) | PASS | `runAsNonRoot: true`, `runAsUser: 1000` |
| Seccomp profile | PASS | `RuntimeDefault` |
| Drop all capabilities | PASS | `capabilities.drop: [ALL]` |
| Read-only root filesystem | PASS | `readOnlyRootFilesystem: true` |
| No privilege escalation | PASS | `allowPrivilegeEscalation: false` |
| Network policy | PASS | Ingress restricted, egress only DNS + HTTPS/443 |
| Resource requests/limits | PASS | CPU and memory bounded |
| Liveness/readiness probes | PASS | HTTP `/health` endpoint |
| HPA configured | PASS | Scales 2-10 replicas |
| PDB configured | PASS | `minAvailable: 1` |
| Topology spread | PASS | Distributes across nodes |
| TLS at ingress | PASS | cert-manager with Let's Encrypt |
| Ingress rate limiting | PASS | `limit-rps: 10`, `limit-connections: 5` |
| Security headers at ingress | PASS | X-Frame-Options, X-Content-Type-Options, etc. |

---

## Part 3: Findings Requiring Action

### CRITICAL-01: HTML Double-Escaping Breaks Legitimate Queries

**Severity:** CRITICAL
**Location:** `security/validation.py` — `_sanitize_string()` + `validate_query()`
**OWASP Category:** Availability / Functionality

**Description:** The `_sanitize_string()` method applies `html.escape()` to all input *before* regex validation. This transforms legitimate characters into HTML entities that then fail the allowed character regex. The escaped value is also what gets sent to the upstream USGS API, corrupting search queries.

**Impact:** Users cannot search for:
- Possessives: `"water's edge"` → `"water&#x27;s edge"` → REJECTED
- Ampersands: `"rock & mineral"` → `"rock &amp; mineral"` → REJECTED
- Quotes: `"water quality"` → `"&quot;water quality&quot;"` → REJECTED
- Author names: `"O'Brien study"` → `"O&#x27;Brien study"` → REJECTED
- Comparisons: `"pH < 7"` → `"pH &lt; 7"` → REJECTED

**Root Cause:** `html.escape()` is applied for "safe logging" but runs before validation and its output is returned as the sanitized query.

**Fix:** Move HTML escaping to logging-only context. The sanitization pipeline should: (1) remove null bytes, (2) normalize unicode, (3) strip whitespace, (4) check injection patterns on raw input, (5) validate against regex on raw input, (6) return the raw (but validated) value. HTML escape only when writing to logs.

---

### HIGH-01: Missing `.dockerignore` File

**Severity:** HIGH
**Location:** Project root

**Description:** No `.dockerignore` exists. During `docker build`, the entire directory tree (including `.git/`, `.venv/`, `.env`, `tests/`, `k8s/`) is sent as build context. This:
1. Leaks `.env` secrets into the Docker build context
2. Significantly slows builds (`.git/` and `.venv/` can be large)
3. Could accidentally include secrets in layers

**Fix:** Add a `.dockerignore` file.

---

### HIGH-02: No Test Runner in Dev Dependencies

**Severity:** HIGH
**Location:** `pyproject.toml`

**Description:** The `[dependency-groups] dev` section only includes `openai>=2.21.0`. `pytest` is not listed, making it impossible to run the test suite without manual installation. The project has 12 test files that cannot be executed out of the box.

**Fix:** Add `pytest` (and optionally `pytest-asyncio`) to dev dependencies.

---

### MEDIUM-01: Dockerfile Uses Deprecated `as` Syntax

**Severity:** MEDIUM
**Location:** `Dockerfile:4`

**Description:** `FROM python:3.12-slim as builder` uses lowercase `as`. While Docker currently accepts this, the canonical syntax is uppercase `AS`. BuildKit and some CI systems may warn about this.

**Fix:** Change to `FROM python:3.12-slim AS builder`.

---

### MEDIUM-02: docker-compose.yml Uses Deprecated `version` Key

**Severity:** MEDIUM
**Location:** `docker-compose.yml:1`

**Description:** `version: '3.8'` is deprecated in modern Docker Compose (v2+). The Compose specification no longer uses the `version` key.

**Fix:** Remove the `version: '3.8'` line.

---

### MEDIUM-03: No LICENSE File

**Severity:** MEDIUM
**Location:** Project root

**Description:** README states "Public domain (as this wraps a US Government API)" but no `LICENSE` file exists. This creates legal ambiguity for users and PyPI publishing may warn.

**Fix:** Add a proper LICENSE file (CC0-1.0 or Unlicense for public domain dedication).

---

### MEDIUM-04: No CI/CD Pipeline

**Severity:** MEDIUM
**Location:** Missing `.github/workflows/`

**Description:** No automated CI/CD is configured. For a security-hardened project, automated testing, linting, and dependency scanning on every push/PR is essential.

**Fix:** Add GitHub Actions workflow for: lint, test, security scan, Docker build.

---

### MEDIUM-05: Schema Transformation Accesses Private SDK Internals

**Severity:** MEDIUM
**Location:** `main.py:398` — `_transform_tool_schemas()`

**Description:** The function accesses `mcp._tool_manager._tools` which is a private attribute of the MCP SDK. This is fragile and may break when the SDK is updated.

**Fix:** Document this dependency and pin the MCP SDK version more tightly, or find a public API for schema access.

---

### MEDIUM-06: Double `.env` Loading

**Severity:** MEDIUM
**Location:** `security/__init__.py:12-17` and `main.py:37-39`

**Description:** The `.env` file is loaded twice — once in `security/__init__.py` and once in `main.py`. Both use `override=False` so the behavior is correct, but it's unnecessary work and confusing.

**Fix:** Remove the loading from `security/__init__.py` since `main.py` loads it first before importing security modules.

---

### LOW-01: No Dependency Vulnerability Scanning

**Severity:** LOW
**Location:** Project configuration

**Description:** No Dependabot, Renovate, or `pip-audit` configuration exists for automated dependency vulnerability scanning.

**Recommendation:** Add `pip-audit` to CI or configure Dependabot for the repository.

---

### LOW-02: Prometheus `/metrics` Endpoint Not Implemented

**Severity:** LOW
**Location:** `DEPLOYMENT.md:209-222`, `k8s/deployment.yaml:19-20`

**Description:** The k8s deployment has Prometheus scrape annotations (`prometheus.io/scrape: "true"`, port 8000) and DEPLOYMENT.md documents a ServiceMonitor, but no `/metrics` endpoint is actually implemented in the server.

**Recommendation:** Either implement a `/metrics` endpoint or remove the Prometheus annotations.

---

### LOW-03: Install Script Lacks OS/Prerequisites Check

**Severity:** LOW
**Location:** `scripts/install.sh`

**Description:** The script doesn't check for prerequisites (Python 3.12+, curl) or handle errors beyond `set -e`.

**Recommendation:** Add prerequisite checks and more informative error handling.

---

### LOW-04: k8s Manifests Reference Placeholder Registry

**Severity:** LOW
**Location:** `k8s/deployment.yaml:34`

**Description:** Image reference is `your-registry/usgs-publications-mcp:v0.2.0`. This is a placeholder that will fail on deploy.

**Recommendation:** Document more prominently that this must be changed, or use kustomize image transformer (which is already partially configured).

---

### LOW-05: `starlette` Imported Inside Function

**Severity:** LOW
**Location:** `main.py:139`

**Description:** `from starlette.responses import JSONResponse` is imported inside the `health_check` route handler. This is a minor style issue but adds latency on first request.

**Recommendation:** Move to top-level imports.

---

## Part 4: Commendations (Security Strengths)

These are notable security implementations that exceed typical MCP server standards:

1. **Defense in depth:** Multiple overlapping security layers (validation, rate limiting, circuit breaker, audit logging, TLS, URL allowlisting)
2. **SIEM-ready audit logging:** Structured JSON with dual timestamps, correlation IDs, severity levels, and SIEM metadata — ready for production monitoring
3. **Comprehensive injection detection:** XSS, SQL, template injection, prototype pollution all detected and logged with specific injection type
4. **Bearer token implementation:** OWASP-compliant with 384-bit entropy, constant-time comparison, rotation with grace period, per-source brute force protection
5. **Container hardening:** Non-root user, read-only filesystem, dropped capabilities, seccomp profiles, no-new-privileges
6. **Network policy:** Kubernetes egress restricted to only DNS and HTTPS/443
7. **OpenAI schema compatibility:** Automatic schema transformation for strict mode
8. **Distributed tracing:** W3C Trace Context compatible, ready for OpenTelemetry integration

---

## Part 5: Remediation Priority

| Priority | Finding | Effort |
|----------|---------|--------|
| 1 | CRITICAL-01: Fix HTML double-escaping in validation | Small |
| 2 | HIGH-01: Add `.dockerignore` | Trivial |
| 3 | HIGH-02: Add pytest to dev dependencies | Trivial |
| 4 | MEDIUM-03: Add LICENSE file | Trivial |
| 5 | MEDIUM-04: Add CI/CD pipeline | Medium |
| 6 | MEDIUM-01: Fix Dockerfile `as` → `AS` | Trivial |
| 7 | MEDIUM-02: Remove docker-compose `version` key | Trivial |
| 8 | MEDIUM-06: Remove double `.env` loading | Trivial |
| 9 | MEDIUM-05: Document SDK private API usage | Small |
| 10 | LOW-01 through LOW-05 | Various |
