// src/middleware/auth.js
// JWT-based authentication for protected (admin) routes

const jwt = require("jsonwebtoken");
const logger = require("../utils/logger");

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  logger.error("FATAL: JWT_SECRET is missing or too short. Set a strong secret in .env");
  if (process.env.NODE_ENV === "production") process.exit(1);
}

/**
 * Middleware: verifies Bearer JWT token on protected routes
 */
function authenticate(req, res, next) {
  const authHeader = req.headers["authorization"];

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      error: "Access denied. Authentication token required.",
    });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ["HS256"],     // Explicitly whitelist algorithm (prevent "alg:none" attack)
      issuer: "purepath-ai",
      audience: "purepath-admin",
    });

    req.user = decoded;
    next();
  } catch (err) {
    logger.warn(`Invalid token attempt: ${err.message} | requestId: ${req.requestId}`);

    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ success: false, error: "Token expired. Please log in again." });
    }
    return res.status(403).json({ success: false, error: "Invalid token." });
  }
}

/**
 * Middleware: role-based access control
 */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      logger.warn(`Unauthorized role access attempt by user: ${req.user?.id} for route ${req.path}`);
      return res.status(403).json({ success: false, error: "Insufficient permissions." });
    }
    next();
  };
}

/**
 * Generate a signed JWT token
 */
function generateToken(payload) {
  return jwt.sign(payload, JWT_SECRET, {
    algorithm: "HS256",
    expiresIn: process.env.JWT_EXPIRES_IN || "24h",
    issuer: "purepath-ai",
    audience: "purepath-admin",
  });
}

module.exports = { authenticate, requireRole, generateToken };
