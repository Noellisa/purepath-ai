// src/routes/reports.js
const express = require("express");
const router = express.Router();

const { authenticate } = require("../middleware/auth");
const { reportLimiter } = require("../middleware/security");
const { validateReport, validateStatusUpdate, validateReportQuery } = require("../middleware/validation");
const { upload, processUploadedImage, handleUploadError } = require("../middleware/upload");
const {
  submitReport,
  getReports,
  getReport,
  updateReportStatus,
  getHotspots,
  getDashboardStats,
} = require("../controllers/reportsController");

// Public routes
router.get("/", validateReportQuery, getReports);
router.get("/hotspots", getHotspots);
router.get("/:id", getReport);

// Public submission (rate limited + validated)
router.post(
  "/",
  reportLimiter,
  upload,
  handleUploadError,
  processUploadedImage,
  validateReport,
  submitReport
);

// Admin-only routes (JWT required)
router.patch("/:id/status", authenticate, validateStatusUpdate, updateReportStatus);
router.get("/admin/stats", authenticate, getDashboardStats);

module.exports = router;
