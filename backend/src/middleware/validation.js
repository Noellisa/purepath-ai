// src/middleware/validation.js
// Input validation and sanitization using express-validator

const { body, param, query, validationResult } = require("express-validator");

/**
 * Returns 422 with error details if validation fails
 */
function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({
      success: false,
      error: "Validation failed",
      details: errors.array().map((e) => ({ field: e.path, message: e.msg })),
    });
  }
  next();
}

// ─────────────────────────────────────────────
// Report submission validators
// ─────────────────────────────────────────────
const validateReport = [
  body("latitude")
    .isFloat({ min: -90, max: 90 })
    .withMessage("Latitude must be between -90 and 90"),

  body("longitude")
    .isFloat({ min: -180, max: 180 })
    .withMessage("Longitude must be between -180 and 180"),

  body("waste_category")
    .isIn(["plastic", "organic", "metal", "mixed", "unknown"])
    .withMessage("Invalid waste category"),

  body("confidence_score")
    .optional()
    .isFloat({ min: 0, max: 1 })
    .withMessage("Confidence score must be between 0 and 1"),

  body("description")
    .optional()
    .isString()
    .trim()
    .isLength({ max: 500 })
    .withMessage("Description must be under 500 characters")
    .escape(), // Escape HTML to prevent XSS

  handleValidationErrors,
];

// ─────────────────────────────────────────────
// Status update validators (admin)
// ─────────────────────────────────────────────
const validateStatusUpdate = [
  param("id")
    .isUUID()
    .withMessage("Invalid report ID"),

  body("status")
    .isIn(["pending", "in_progress", "cleaned"])
    .withMessage("Status must be pending, in_progress, or cleaned"),

  handleValidationErrors,
];

// ─────────────────────────────────────────────
// Auth validators
// ─────────────────────────────────────────────
const validateLogin = [
  body("username")
    .isString()
    .trim()
    .isLength({ min: 3, max: 50 })
    .withMessage("Username must be 3–50 characters")
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage("Username may only contain letters, numbers, underscores, and hyphens"),

  body("password")
    .isString()
    .isLength({ min: 8, max: 128 })
    .withMessage("Password must be 8–128 characters"),

  handleValidationErrors,
];

// ─────────────────────────────────────────────
// Query param validators for report listing
// ─────────────────────────────────────────────
const validateReportQuery = [
  query("status")
    .optional()
    .isIn(["pending", "in_progress", "cleaned"])
    .withMessage("Invalid status filter"),

  query("waste_category")
    .optional()
    .isIn(["plastic", "organic", "metal", "mixed", "unknown"])
    .withMessage("Invalid waste category filter"),

  query("limit")
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage("Limit must be between 1 and 100"),

  query("offset")
    .optional()
    .isInt({ min: 0 })
    .withMessage("Offset must be a non-negative integer"),

  handleValidationErrors,
];

module.exports = {
  validateReport,
  validateStatusUpdate,
  validateLogin,
  validateReportQuery,
};
