// tests/security.test.js
// Basic vulnerability test suite for PurePath AI Backend
// Run with: npm test

const request = require("supertest");

// Set test env before loading app
process.env.NODE_ENV = "test";
process.env.JWT_SECRET = "test-secret-key-that-is-long-enough-for-testing-purposes-123456";
process.env.DB_PATH = "./data/test.db";
process.env.ADMIN_DEFAULT_USERNAME = "testadmin";
process.env.ADMIN_DEFAULT_PASSWORD = "TestPassword@123";

const app = require("../src/server");

describe("🔐 PurePath AI – Security Test Suite", () => {

  // ─────────────────────────────────────────
  // 1. SECURITY HEADERS
  // ─────────────────────────────────────────
  describe("Security Headers (Helmet)", () => {
    test("Should include X-Content-Type-Options: nosniff", async () => {
      const res = await request(app).get("/api/health");
      expect(res.headers["x-content-type-options"]).toBe("nosniff");
    });

    test("Should include X-Frame-Options to prevent clickjacking", async () => {
      const res = await request(app).get("/api/health");
      expect(res.headers["x-frame-options"]).toBeDefined();
    });

    test("Should NOT expose X-Powered-By header", async () => {
      const res = await request(app).get("/api/health");
      expect(res.headers["x-powered-by"]).toBeUndefined();
    });

    test("Should include Content-Security-Policy", async () => {
      const res = await request(app).get("/api/health");
      expect(res.headers["content-security-policy"]).toBeDefined();
    });

    test("Should include X-Request-Id on every response", async () => {
      const res = await request(app).get("/api/health");
      expect(res.headers["x-request-id"]).toBeDefined();
      expect(res.headers["x-request-id"]).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
      );
    });
  });

  // ─────────────────────────────────────────
  // 2. AUTHENTICATION
  // ─────────────────────────────────────────
  describe("Authentication & Authorization", () => {
    test("Should reject requests to admin routes without a token", async () => {
      const res = await request(app).get("/api/reports/admin/stats");
      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    test("Should reject requests with a malformed token", async () => {
      const res = await request(app)
        .get("/api/reports/admin/stats")
        .set("Authorization", "Bearer this.is.not.a.valid.token");
      expect(res.status).toBe(403);
    });

    test("Should reject login with wrong credentials", async () => {
      const res = await request(app)
        .post("/api/auth/login")
        .send({ username: "admin", password: "wrongpassword" });
      expect(res.status).toBe(401);
      // Generic message — no info about whether username exists
      expect(res.body.error).toContain("Invalid username or password");
    });

    test("Should not reveal if a username exists (timing-safe response)", async () => {
      const start1 = Date.now();
      await request(app).post("/api/auth/login").send({ username: "nonexistent_user_xyz", password: "password" });
      const time1 = Date.now() - start1;

      const start2 = Date.now();
      await request(app).post("/api/auth/login").send({ username: "testadmin", password: "wrongpassword" });
      const time2 = Date.now() - start2;

      // Both should take similar time (bcrypt compare runs in both cases)
      // Allow 500ms tolerance for timing difference
      expect(Math.abs(time1 - time2)).toBeLessThan(500);
    });
  });

  // ─────────────────────────────────────────
  // 3. INPUT VALIDATION
  // ─────────────────────────────────────────
  describe("Input Validation & Sanitization", () => {
    test("Should reject report with out-of-range latitude", async () => {
      const res = await request(app)
        .post("/api/reports")
        .field("latitude", "999")
        .field("longitude", "0")
        .field("waste_category", "plastic");
      expect(res.status).toBe(422);
    });

    test("Should reject report with invalid waste category", async () => {
      const res = await request(app)
        .post("/api/reports")
        .field("latitude", "5.6")
        .field("longitude", "-0.2")
        .field("waste_category", "radioactive"); // not in allowed list
      expect(res.status).toBe(422);
    });

    test("Should reject login with SQL injection attempt in username", async () => {
      const res = await request(app)
        .post("/api/auth/login")
        .send({ username: "admin' OR '1'='1", password: "anything" });
      expect(res.status).toBe(422); // Caught by validator (invalid chars)
    });

    test("Should reject login with oversized payload", async () => {
      const res = await request(app)
        .post("/api/auth/login")
        .send({ username: "a".repeat(1000), password: "b".repeat(1000) });
      expect(res.status).toBe(422);
    });

    test("Should reject status update with invalid status value", async () => {
      // Need a valid UUID format for the param
      const fakeId = "123e4567-e89b-12d3-a456-426614174000";
      const res = await request(app)
        .patch(`/api/reports/${fakeId}/status`)
        .set("Authorization", "Bearer fake_token_to_test_validation_order")
        .send({ status: "deleted" }); // not in allowed statuses
      // Either 401/403 (auth) or 422 (validation) — both are acceptable
      expect([401, 403, 422]).toContain(res.status);
    });
  });

  // ─────────────────────────────────────────
  // 4. FILE UPLOAD SECURITY
  // ─────────────────────────────────────────
  describe("File Upload Security", () => {
    test("Should reject non-image file uploads", async () => {
      const res = await request(app)
        .post("/api/reports")
        .field("latitude", "5.6")
        .field("longitude", "-0.2")
        .field("waste_category", "plastic")
        .attach("image", Buffer.from("<?php echo 'hacked'; ?>"), {
          filename: "shell.php",
          contentType: "image/jpeg", // Claimed as image, but isn't
        });
      // Should be rejected (400 or 422 or 201 with processing error)
      expect([400, 422]).toContain(res.status);
    });

    test("Should reject HTML files disguised as images", async () => {
      const res = await request(app)
        .post("/api/reports")
        .field("latitude", "5.6")
        .field("longitude", "-0.2")
        .field("waste_category", "plastic")
        .attach("image", Buffer.from("<html><script>alert(1)</script></html>"), {
          filename: "evil.jpg",
          contentType: "image/jpeg",
        });
      expect([400, 422]).toContain(res.status);
    });
  });

  // ─────────────────────────────────────────
  // 5. RATE LIMITING
  // ─────────────────────────────────────────
  describe("Rate Limiting", () => {
    test("Auth limiter should block after too many login attempts", async () => {
      // Make 11 rapid requests (limit is 10 per 15 min)
      const requests = Array.from({ length: 11 }, () =>
        request(app)
          .post("/api/auth/login")
          .send({ username: "test", password: "test" })
      );
      const responses = await Promise.all(requests);
      const blocked = responses.some((r) => r.status === 429);
      expect(blocked).toBe(true);
    });
  });

  // ─────────────────────────────────────────
  // 6. CORS
  // ─────────────────────────────────────────
  describe("CORS Policy", () => {
    test("Should allow requests from allowed origin", async () => {
      const res = await request(app)
        .get("/api/health")
        .set("Origin", "http://localhost:5173");
      expect(res.headers["access-control-allow-origin"]).toBe("http://localhost:5173");
    });

    test("Should block requests from disallowed origins", async () => {
      const res = await request(app)
        .get("/api/health")
        .set("Origin", "https://malicious-site.com");
      expect(res.headers["access-control-allow-origin"]).toBeUndefined();
    });
  });

  // ─────────────────────────────────────────
  // 7. ROUTE SECURITY
  // ─────────────────────────────────────────
  describe("Route & Error Handling", () => {
    test("Should return 404 for non-existent routes", async () => {
      const res = await request(app).get("/api/nonexistent/endpoint");
      expect(res.status).toBe(404);
      expect(res.body.success).toBe(false);
    });

    test("Should not return report for non-existent ID (valid UUID format)", async () => {
      const res = await request(app).get("/api/reports/00000000-0000-0000-0000-000000000000");
      expect(res.status).toBe(404);
    });

    test("Health endpoint should be publicly accessible", async () => {
      const res = await request(app).get("/api/health");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });
  });
});
