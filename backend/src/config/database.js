// src/config/database.js
// SQLite database initialization with parameterized queries throughout

const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const fs = require("fs");
const logger = require("../utils/logger");

const DB_PATH = process.env.DB_PATH || "./data/purepath.db";

// Ensure data directory exists
const dataDir = path.dirname(DB_PATH);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

let db;

function getDb() {
  if (!db) {
    db = new sqlite3.Database(DB_PATH, (err) => {
      if (err) {
        logger.error("Database connection failed:", err.message);
        process.exit(1);
      }
      logger.info(`Connected to SQLite database at ${DB_PATH}`);
    });

    // Enable WAL mode for better concurrency and security
    db.run("PRAGMA journal_mode=WAL");
    db.run("PRAGMA foreign_keys=ON");
  }
  return db;
}

function initializeDatabase() {
  return new Promise((resolve, reject) => {
    const database = getDb();

    database.serialize(() => {
      // --- Users table (for municipal admin accounts) ---
      database.run(`
        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY,
          username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'admin' CHECK(role IN ('admin', 'moderator')),
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          last_login DATETIME,
          is_active INTEGER DEFAULT 1
        )
      `);

      // --- Waste reports table ---
      database.run(`
        CREATE TABLE IF NOT EXISTS reports (
          id TEXT PRIMARY KEY,
          latitude REAL NOT NULL,
          longitude REAL NOT NULL,
          waste_category TEXT NOT NULL CHECK(waste_category IN ('plastic','organic','metal','mixed','unknown')),
          confidence_score REAL,
          risk_score INTEGER DEFAULT 0,
          status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','in_progress','cleaned')),
          image_filename TEXT,
          image_hash TEXT,
          description TEXT,
          is_hotspot INTEGER DEFAULT 0,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_by TEXT,
          reporter_ip_hash TEXT
        )
      `);

      // --- Hotspot clusters table ---
      database.run(`
        CREATE TABLE IF NOT EXISTS hotspots (
          id TEXT PRIMARY KEY,
          center_lat REAL NOT NULL,
          center_lng REAL NOT NULL,
          radius_meters REAL DEFAULT 200,
          report_count INTEGER DEFAULT 1,
          risk_level TEXT DEFAULT 'low' CHECK(risk_level IN ('low','medium','high','critical')),
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);

      // --- Audit log for security events ---
      database.run(`
        CREATE TABLE IF NOT EXISTS audit_log (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          event_type TEXT NOT NULL,
          event_data TEXT,
          ip_hash TEXT,
          user_id TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `, (err) => {
        if (err) return reject(err);
        logger.info("Database schema initialized successfully");
        resolve(database);
      });
    });
  });
}

module.exports = { getDb, initializeDatabase };
