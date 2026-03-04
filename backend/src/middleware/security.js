// src/middleware/security.js
// Core security middleware stack for PurePath AI

const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const logger = require("../utils/logger");

// ─────────────────────────────────────────────
// 1. HELMET – sets secure HTTP response headers
// ─────────────────────────────────────────────
const helmetMiddleware = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  // Prevent browsers from MIME-sniffing
  noSniff: true,
  // Clickjacking protection
  frameguard: { action: "deny" },
  // Disable X-Powered-By to hide Express
  hidePoweredBy: true,
  // Strict-Transport-Security (enable HTTPS in prod)
  hsts: process.env.NODE_ENV === "production" ? { maxAge: 31536000, includeSubDomains: true } : false,
  // Referrer Policy
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
});

// ─────────────────────────────────────────────
// 2. CORS – restrict allowed origins
// ─────────────────────────────────────────────
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "http://localhost:5173")
  .split(",")
  .map((o) => o.trim());

const corsMiddleware = cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (e.g., mobile apps, Postman in dev)
    if (!origin) {
      if (process.env.NODE_ENV === "production") {
        return callback(new Error("Origin required in production"), false);
      }
      return callback(null, true);
    }
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    logger.warn(`CORS blocked request from origin: ${origin}`);
    return callback(new Error(`CORS policy: origin ${origin} not allowed`), false);
  },
  methods: ["GET", "POST", "PATCH", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
  exposedHeaders: ["X-Request-Id"],
  credentials: true,
  maxAge: 86400, // Cache preflight for 24 hours
});

// ─────────────────────────────────────────────
// 3. RATE LIMITERS
// ─────────────────────────────────────────────
const windowMs = parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000;
const maxRequests = parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100;

// General API rate limiter
const apiLimiter = rateLimit({
  windowMs,
  max: maxRequests,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: "Too many requests. Please try again later.",
  },
  handler: (req, res, next, options) => {
    logger.warn(`Rate limit exceeded for IP hash: ${hashIp(req.ip)}`);
    res.status(429).json(options.message);
  },
});

// Stricter limiter for auth endpoints (prevent brute force)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: {
    success: false,
    error: "Too many login attempts. Account temporarily locked for 15 minutes.",
  },
  handler: (req, res, next, options) => {
    logger.warn(`AUTH rate limit exceeded for IP hash: ${hashIp(req.ip)}`);
    res.status(429).json(options.message);
  },
});

// Stricter limiter for report submission (prevent spam)
const reportLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20,
  message: {
    success: false,
    error: "Report submission limit reached. Please wait before submitting more reports.",
  },
});

// ─────────────────────────────────────────────
// 4. REQUEST ID – trace requests in logs
// ─────────────────────────────────────────────
const requestId = (req, res, next) => {
  const id = crypto.randomUUID();
  req.requestId = id;
  res.setHeader("X-Request-Id", id);
  next();
};

// ─────────────────────────────────────────────
// 5. HELPER – hash IPs before logging (GDPR-friendly)
// ─────────────────────────────────────────────
function hashIp(ip) {
  if (!ip) return "unknown";
  return crypto.createHash("sha256").update(ip + (process.env.JWT_SECRET || "salt")).digest("hex").slice(0, 16);
}

module.exports = {
  helmetMiddleware,
  corsMiddleware,
  apiLimiter,
  authLimiter,
  reportLimiter,
  requestId,
  hashIp,
};
