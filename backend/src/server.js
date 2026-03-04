// src/server.js
// PurePath AI – Main Application Entry Point

require("dotenv").config();
const express = require("express");
const compression = require("compression");
const morgan = require("morgan");
const path = require("path");

const logger = require("./utils/logger");
const { initializeDatabase } = require("./config/database");
const { seedAdminIfNeeded } = require("./controllers/authController");
const {
  helmetMiddleware,
  corsMiddleware,
  apiLimiter,
  requestId,
} = require("./middleware/security");

// Routes
const reportRoutes = require("./routes/reports");
const authRoutes   = require("./routes/auth");

// ─────────────────────────────────────────────
// EXPRESS APP SETUP
// ─────────────────────────────────────────────
const app = express();
const PORT = process.env.PORT || 5000;

// ─── Security Middleware (applied first) ───
app.set("trust proxy", 1); // Trust first proxy for rate limiting by real IP
app.use(requestId);
app.use(helmetMiddleware);
app.use(corsMiddleware);

// ─── Compression ───
app.use(compression());

// ─── Body Parsers (size limits to prevent payload bombs) ───
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true, limit: "10kb" }));

// ─── HTTP Access Logging (Morgan → Winston) ───
app.use(
  morgan("combined", {
    stream: { write: (msg) => logger.info(msg.trim()) },
    // Skip health check logs to reduce noise
    skip: (req) => req.path === "/api/health",
  })
);

// ─── Global Rate Limiter ───
app.use("/api/", apiLimiter);

// ─── Static Files (processed images) ───
// Served with security headers; no directory listing
app.use(
  "/uploads",
  (req, res, next) => {
    // Only allow .jpg files (we re-encode everything to JPEG)
    if (!req.path.match(/^\/[a-f0-9-]{36}\.jpg$/)) {
      return res.status(403).json({ success: false, error: "Forbidden" });
    }
    next();
  },
  express.static(path.join(__dirname, "../uploads"), {
    dotfiles: "deny",
    index: false,
    redirect: false,
  })
);

// ─────────────────────────────────────────────
// API ROUTES
// ─────────────────────────────────────────────
app.use("/api/auth",    authRoutes);
app.use("/api/reports", reportRoutes);

// ─── Health Check (public, no auth) ───
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    service: "PurePath AI API",
    version: "1.0.0",
    timestamp: new Date().toISOString(),
    uptime: `${Math.floor(process.uptime())}s`,
  });
});

// ─────────────────────────────────────────────
// ERROR HANDLERS
// ─────────────────────────────────────────────

// 404 Handler
app.use((req, res) => {
  res.status(404).json({ success: false, error: `Route ${req.method} ${req.path} not found.` });
});

// Global Error Handler
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  logger.error(`Unhandled error: ${err.message} | requestId: ${req.requestId}`, err);

  // Don't leak stack traces or internal error details in production
  const isProd = process.env.NODE_ENV === "production";
  res.status(err.status || 500).json({
    success: false,
    error: isProd ? "An internal server error occurred." : err.message,
    ...(isProd ? {} : { stack: err.stack }),
  });
});

// ─────────────────────────────────────────────
// STARTUP
// ─────────────────────────────────────────────
async function start() {
  try {
    await initializeDatabase();
    await seedAdminIfNeeded();

    const server = app.listen(PORT, () => {
      logger.info(`✅ PurePath AI API running on http://localhost:${PORT}`);
      logger.info(`   Environment : ${process.env.NODE_ENV || "development"}`);
      logger.info(`   API Base    : http://localhost:${PORT}/api`);
    });

    // Graceful shutdown
    process.on("SIGTERM", () => {
      logger.info("SIGTERM received. Shutting down gracefully...");
      server.close(() => {
        logger.info("Server closed.");
        process.exit(0);
      });
    });
  } catch (err) {
    logger.error("Server startup failed:", err);
    process.exit(1);
  }
}

start();

module.exports = app; // Export for testing
