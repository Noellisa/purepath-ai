# PurePath AI – Security Documentation
**Team 23 | Capstone Project | Women Techsters Fellowship – Cybersecurity Track**
**SDG 6 – Clean Water and Sanitation**

---

## Table of Contents
1. [Threat Assessment](#1-threat-assessment)
2. [Secure API Configuration](#2-secure-api-configuration)
3. [Data Protection](#3-data-protection)
4. [Security Testing](#4-security-testing)
5. [Setup & Deployment Checklist](#5-setup--deployment-checklist)

---

## 1. Threat Assessment

### 1.1 Threat Model Overview (STRIDE)

PurePath AI is a public-facing platform that accepts user-uploaded images and GPS data, making it a target for several common web attack vectors.

| Threat Category | Description | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| **Spoofing** | Attacker impersonates admin to change report statuses | Medium | High | JWT auth + bcrypt password hashing |
| **Tampering** | Malicious data injected into reports (SQL injection, XSS) | High | High | Parameterized queries, input validation, CSP |
| **Repudiation** | Admin denies making status changes | Low | Medium | Audit log with `updated_by` field |
| **Information Disclosure** | Sensitive data exposed via API responses or logs | Medium | High | Response filtering, IP hashing in logs |
| **Denial of Service** | Flood of fake reports or login attempts | High | Medium | Rate limiting on all endpoints |
| **Elevation of Privilege** | Citizen user accesses admin-only endpoints | Medium | High | Role-based access control (RBAC) |

### 1.2 Attack Surface Identification

```
Internet
    │
    ▼
[Reverse Proxy / CDN]          ← TLS termination, DDoS protection
    │
    ▼
[Express API Server]
    ├── POST /api/reports       ← PUBLIC: Image upload attack surface
    ├── POST /api/auth/login    ← PUBLIC: Brute force attack surface
    ├── GET  /api/reports       ← PUBLIC: Data enumeration risk
    ├── PATCH /api/reports/:id  ← PRIVATE: Auth bypass risk
    └── GET  /uploads/*         ← STATIC: Path traversal risk
    │
    ▼
[SQLite Database]              ← SQL injection risk
    │
    ▼
[Filesystem (uploads/)]        ← Malicious file upload risk
```

### 1.3 High-Priority Risks

**Risk 1 – Malicious File Upload**
An attacker could upload a disguised file (e.g., a PHP shell as a `.jpg`) hoping to execute it on the server. This is mitigated through:
- MIME type whitelisting (JPEG, PNG, WebP only)
- Magic byte verification (reading the actual file header)
- Re-encoding all uploads through Sharp (sanitizes content)
- UUID-based filenames (no user-controlled path segments)

**Risk 2 – SQL Injection**
A malicious user could craft inputs to manipulate database queries. Mitigated by:
- 100% parameterized queries throughout — no string concatenation
- SQLite foreign key enforcement
- Input validation before any DB operation

**Risk 3 – Authentication Brute Force**
Repeated login attempts to guess admin passwords. Mitigated by:
- Rate limiter: max 10 attempts per 15 minutes per IP
- bcrypt with 12 rounds (computationally expensive per attempt)
- Timing-safe response (same response time whether user exists or not)

**Risk 4 – Cross-Site Scripting (XSS)**
User-provided text (description field) injected into the dashboard. Mitigated by:
- `.escape()` on all text inputs (HTML entity encoding)
- Strict Content-Security-Policy header disallowing inline scripts

---

## 2. Secure API Configuration

### 2.1 HTTP Security Headers (Helmet)

Every API response includes these headers automatically:

| Header | Value | Purpose |
|---|---|---|
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-type sniffing |
| `X-Frame-Options` | `DENY` | Prevents clickjacking via iframes |
| `X-Powered-By` | *(removed)* | Hides Express.js from attackers |
| `Content-Security-Policy` | See below | Restricts resource loading |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Controls referrer data |
| `X-Request-Id` | UUID | Unique ID for tracing each request |

**Content-Security-Policy:**
```
default-src 'self';
script-src 'self';
img-src 'self' data: blob:;
connect-src 'self';
object-src 'none';
```

### 2.2 CORS Configuration

Only whitelisted origins are allowed to make API calls:
```
Allowed: http://localhost:5173 (development)
         http://localhost:3000 (optional dev)
```
In production, replace these with your actual deployed frontend domain.

### 2.3 Rate Limiting

| Endpoint Group | Window | Max Requests | Purpose |
|---|---|---|---|
| All `/api/*` routes | 15 min | 100 | General DoS protection |
| `POST /api/auth/login` | 15 min | 10 | Brute force protection |
| `POST /api/reports` | 1 hour | 20 | Spam/flood protection |

### 2.4 JWT Token Security

- Algorithm: `HS256` (explicitly whitelisted to prevent `alg:none` attacks)
- Issuer: `purepath-ai`
- Audience: `purepath-admin`
- Expiry: 24 hours (configurable)
- Secret: Minimum 64 characters, stored only in `.env`

### 2.5 Environment Variables

Sensitive configuration is never hardcoded. All secrets are read from `.env`:
```
JWT_SECRET          – Token signing key (min 64 chars)
ADMIN_DEFAULT_PASSWORD – Changed on first deploy
DB_PATH             – Database file location
```

**Never commit `.env` to git.** The `.gitignore` file excludes it.

---

## 3. Data Protection

### 3.1 Input Validation

Every piece of user input is validated before processing:

| Field | Validation Rules |
|---|---|
| `latitude` | Float, range -90 to 90 |
| `longitude` | Float, range -180 to 180 |
| `waste_category` | Must be one of: plastic, organic, metal, mixed, unknown |
| `confidence_score` | Float, range 0.0 to 1.0 |
| `description` | String, max 500 chars, HTML-escaped |
| `username` | 3–50 chars, alphanumeric + `_-` only |
| `password` | 8–128 chars |
| Report ID (URL param) | Must be valid UUID format |
| Pagination params | Positive integers, max limit of 100 |

**Validation is enforced server-side.** Frontend validation is a UX convenience only and cannot be relied upon for security.

### 3.2 Secure Image Handling (5-Layer Pipeline)

When a user uploads a waste photo, it passes through 5 security layers:

```
User Upload
    │
    ▼ Layer 1: MIME Type Check
    │   Accept only: image/jpeg, image/png, image/webp
    │
    ▼ Layer 2: File Extension Check
    │   Accept only: .jpg, .jpeg, .png, .webp
    │
    ▼ Layer 3: Magic Byte Verification
    │   Read file header bytes to confirm actual file type
    │   (catches files with spoofed Content-Type)
    │
    ▼ Layer 4: Sharp Re-encoding
    │   • Resize to max 1920×1080
    │   • Re-encode to JPEG (strips embedded scripts/payloads)
    │   • Strip ALL EXIF/GPS metadata (privacy protection)
    │   • withMetadata(false)
    │
    ▼ Layer 5: Safe Storage
        • Random UUID filename (e.g., 7f3a2b1c-....jpg)
        • Stored outside web root
        • Served only via validated static route
        • Path regex: /^\/[a-f0-9-]{36}\.jpg$/
```

**Why strip EXIF data?**
JPEG files often contain embedded GPS coordinates, device model, timestamp, and sometimes user thumbnails. Displaying this data publicly would be a serious privacy violation.

### 3.3 Password Storage

Admin passwords are hashed using **bcrypt** with **12 rounds** (work factor). This means:
- Passwords are never stored in plain text
- 12 rounds = ~250ms per hash (computationally expensive for attackers)
- Even a database breach does not expose passwords

### 3.4 Privacy-Preserving Logging

IP addresses are **never logged in plain text**. Before storage or logging, IPs are hashed:
```javascript
SHA-256(ip + JWT_SECRET).slice(0, 16)
```
This allows correlation within a session without storing identifiable data (GDPR-aligned).

### 3.5 Database Security

- All queries use **parameterized statements** (zero string concatenation)
- SQLite `PRAGMA foreign_keys = ON` enforced
- WAL (Write-Ahead Logging) mode for safe concurrent access
- Database file stored outside the web-accessible directory

---

## 4. Security Testing

### 4.1 Running the Test Suite

```bash
# Install dependencies
npm install

# Run full security test suite
npm test

# Run with verbose output
npx jest --verbose

# Run specific test group
npx jest --testNamePattern="Security Headers"
```

### 4.2 Test Coverage Summary

The test suite (`tests/security.test.js`) covers 7 categories:

| # | Category | Tests |
|---|---|---|
| 1 | Security Headers | X-Content-Type-Options, X-Frame-Options, CSP, X-Request-Id, no X-Powered-By |
| 2 | Authentication | Token required, malformed token, wrong credentials, timing-safe response |
| 3 | Input Validation | Out-of-range coordinates, invalid category, SQL injection attempt, oversized payload |
| 4 | File Upload | PHP shell disguised as image, HTML file disguised as image |
| 5 | Rate Limiting | Auth endpoint blocks after 10 attempts |
| 6 | CORS | Allowed origin accepted, blocked origin rejected |
| 7 | Route Security | 404 for unknown routes, 404 for missing report, health check accessible |

### 4.3 Manual Security Testing Checklist

These checks should be done manually before any demo or deployment:

**Authentication Tests**
- [ ] Accessing `/api/reports/admin/stats` without token returns 401
- [ ] Using an expired JWT returns 401 with "Token expired" message
- [ ] Login with wrong password 10+ times triggers 429 Too Many Requests
- [ ] Successful login returns a token that works on protected routes

**Input Injection Tests**
- [ ] Submit report with `description: "<script>alert(1)</script>"` — verify it's stored escaped
- [ ] Submit report with `latitude: "1; DROP TABLE reports;--"` — verify 422 validation error
- [ ] Submit login with `username: "' OR 1=1--"` — verify 422 validation error

**File Upload Tests**
- [ ] Upload a `.txt` file — verify rejection
- [ ] Upload a `.php` file with `image/jpeg` Content-Type — verify rejection
- [ ] Upload a legitimate JPEG — verify it processes and appears on dashboard
- [ ] Check that uploaded files have UUID names (not original filenames)
- [ ] Check that EXIF GPS data is stripped from uploaded images

**Header Tests (Use Browser DevTools or curl)**
```bash
curl -I http://localhost:5000/api/health
# Verify presence of: x-content-type-options, x-frame-options, content-security-policy
# Verify absence of: x-powered-by
```

**Rate Limit Test**
```bash
for i in {1..12}; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST http://localhost:5000/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"test","password":"test"}';
done
# Expected: First 10 return 401, then 429 (Too Many Requests)
```

### 4.4 Vulnerability Documentation

| Vulnerability | OWASP Category | Status | Mitigation |
|---|---|---|---|
| SQL Injection | A03:2021 | ✅ Mitigated | Parameterized queries throughout |
| Broken Authentication | A07:2021 | ✅ Mitigated | bcrypt, JWT, rate limiting |
| Sensitive Data Exposure | A02:2021 | ✅ Mitigated | IP hashing, EXIF stripping, no password logging |
| XML/File Upload Attacks | A05:2021 | ✅ Mitigated | Magic byte check, Sharp re-encoding |
| XSS (Stored) | A03:2021 | ✅ Mitigated | Input escaping, strict CSP |
| Clickjacking | A05:2021 | ✅ Mitigated | X-Frame-Options: DENY |
| MIME Sniffing | A05:2021 | ✅ Mitigated | X-Content-Type-Options: nosniff |
| CORS Misconfiguration | A05:2021 | ✅ Mitigated | Origin whitelist |
| Brute Force | A07:2021 | ✅ Mitigated | Auth rate limiter (10/15min) |
| Path Traversal | A01:2021 | ✅ Mitigated | UUID filenames, regex route guard |
| Information Leakage | A09:2021 | ✅ Mitigated | Generic error messages in production |

---

## 5. Setup & Deployment Checklist

### Development Setup
```bash
git clone <repo>
cd purepath-backend
npm install
cp .env.example .env
# Edit .env and set a strong JWT_SECRET and ADMIN_DEFAULT_PASSWORD
npm run dev
```

### Pre-Deployment Checklist
- [ ] `NODE_ENV=production` is set
- [ ] `JWT_SECRET` is a randomly generated 64+ character string
- [ ] `ADMIN_DEFAULT_PASSWORD` changed from default
- [ ] `ALLOWED_ORIGINS` updated to production frontend domain
- [ ] `.env` is NOT committed to version control
- [ ] HTTPS/TLS is configured on the server or reverse proxy
- [ ] `uploads/` directory is not publicly browsable
- [ ] Log files are excluded from public access
- [ ] Database file is outside web-accessible directories

### Generating a Secure JWT_SECRET
```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

---

*Security documentation maintained by Team 23 – Women Techsters Fellowship, Cybersecurity Track.*
*References: OWASP Top 10 (2021), NIST SP 800-63B, GDPR Article 25 (Privacy by Design)*
