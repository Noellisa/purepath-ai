// src/controllers/authController.js
// Admin authentication: login, token refresh, profile

const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");
const { getDb } = require("../config/database");
const { generateToken } = require("../middleware/auth");
const { hashIp } = require("../middleware/security");
const logger = require("../utils/logger");

const BCRYPT_ROUNDS = 12; // Strong work factor

/**
 * Seed a default admin account on first run
 * Called from server startup if no users exist
 */
async function seedAdminIfNeeded() {
  const db = getDb();
  const username = process.env.ADMIN_DEFAULT_USERNAME || "admin";
  const rawPassword = process.env.ADMIN_DEFAULT_PASSWORD;

  if (!rawPassword || rawPassword === "CHANGE_ME_STRONG_PASSWORD") {
    logger.warn("⚠️  ADMIN_DEFAULT_PASSWORD is not set or is using the default. Change it in .env immediately!");
    return;
  }

  return new Promise((resolve) => {
    db.get("SELECT id FROM users WHERE username = ?", [username], async (err, row) => {
      if (row) return resolve(); // Admin already exists

      const hash = await bcrypt.hash(rawPassword, BCRYPT_ROUNDS);
      db.run(
        "INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)",
        [uuidv4(), username, hash, "admin"],
        (err) => {
          if (err) logger.error("Failed to seed admin:", err.message);
          else logger.info(`Default admin account created: "${username}"`);
          resolve();
        }
      );
    });
  });
}

/**
 * POST /api/auth/login
 */
async function login(req, res) {
  const db = getDb();
  const { username, password } = req.body;

  // Use a fixed-time lookup to avoid timing attacks on usernames
  db.get(
    "SELECT id, username, password_hash, role, is_active FROM users WHERE username = ?",
    [username],
    async (err, user) => {
      if (err) {
        logger.error(`Login DB error: ${err.message}`);
        return res.status(500).json({ success: false, error: "Server error during login." });
      }

      // Always run bcrypt compare to prevent timing attacks
      // (run compare even if user not found, against a dummy hash)
      const dummyHash = "$2b$12$dummyhashfortimingatttackprevention1234567890";
      const hashToCheck = user ? user.password_hash : dummyHash;

      const isValid = await bcrypt.compare(password, hashToCheck);

      if (!user || !isValid || !user.is_active) {
        logger.warn(`Failed login for username: "${username}" from IP hash: ${hashIp(req.ip)}`);
        // Generic message — do not reveal if username exists
        return res.status(401).json({
          success: false,
          error: "Invalid username or password.",
        });
      }

      // Update last login timestamp
      db.run("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", [user.id]);

      const token = generateToken({ id: user.id, username: user.username, role: user.role });

      // Log to audit trail
      db.run(
        "INSERT INTO audit_log (event_type, event_data, ip_hash, user_id) VALUES (?, ?, ?, ?)",
        ["LOGIN_SUCCESS", JSON.stringify({ username }), hashIp(req.ip), user.id]
      );

      logger.info(`Admin login: ${user.username} (${user.id})`);

      res.json({
        success: true,
        data: {
          token,
          user: { id: user.id, username: user.username, role: user.role },
          expires_in: process.env.JWT_EXPIRES_IN || "24h",
        },
      });
    }
  );
}

/**
 * GET /api/auth/profile
 * Returns current authenticated user info
 */
function getProfile(req, res) {
  res.json({
    success: true,
    data: {
      id: req.user.id,
      username: req.user.username,
      role: req.user.role,
    },
  });
}

module.exports = { login, getProfile, seedAdminIfNeeded };
