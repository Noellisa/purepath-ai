// src/utils/logger.js
// Centralized logging – never log sensitive data (passwords, tokens, full IPs)

const winston = require("winston");
const path = require("path");
const fs = require("fs");

const LOG_DIR = process.env.LOG_DIR || "./logs";
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

const { combine, timestamp, printf, colorize, errors } = winston.format;

const logFormat = printf(({ level, message, timestamp, stack }) => {
  return `${timestamp} [${level}]: ${stack || message}`;
});

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: combine(
    timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
    errors({ stack: true }),
    logFormat
  ),
  transports: [
    // Console output (colorized in dev)
    new winston.transports.Console({
      format: combine(colorize(), logFormat),
      silent: process.env.NODE_ENV === "test",
    }),
    // Persistent log files
    new winston.transports.File({
      filename: path.join(LOG_DIR, "error.log"),
      level: "error",
      maxsize: 5 * 1024 * 1024, // 5MB
      maxFiles: 5,
    }),
    new winston.transports.File({
      filename: path.join(LOG_DIR, "combined.log"),
      maxsize: 10 * 1024 * 1024,
      maxFiles: 10,
    }),
    // Security events in their own file
    new winston.transports.File({
      filename: path.join(LOG_DIR, "security.log"),
      level: "warn",
      maxsize: 5 * 1024 * 1024,
      maxFiles: 10,
    }),
  ],
});

module.exports = logger;
