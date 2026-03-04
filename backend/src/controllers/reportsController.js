// src/controllers/reportsController.js
// Business logic for waste report CRUD and hotspot detection

const { v4: uuidv4 } = require("uuid");
const { getDb } = require("../config/database");
const { hashIp } = require("../middleware/security");
const logger = require("../utils/logger");

// ─────────────────────────────────────────────
// SUBMIT A NEW WASTE REPORT
// ─────────────────────────────────────────────
async function submitReport(req, res) {
  const db = getDb();
  const { latitude, longitude, waste_category, confidence_score, description } = req.body;
  const reportId = uuidv4();

  const imageFilename = req.file?.safeFilename || null;
  const imageHash     = req.file?.imageHash || null;
  const reporterIpHash = hashIp(req.ip);

  // Calculate risk score
  const riskScore = await calculateRiskScore(db, parseFloat(latitude), parseFloat(longitude));

  return new Promise((resolve) => {
    // All values passed as parameterized query bindings — no SQL injection possible
    db.run(
      `INSERT INTO reports
        (id, latitude, longitude, waste_category, confidence_score, risk_score,
         image_filename, image_hash, description, reporter_ip_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        reportId,
        parseFloat(latitude),
        parseFloat(longitude),
        waste_category,
        confidence_score ? parseFloat(confidence_score) : null,
        riskScore,
        imageFilename,
        imageHash,
        description || null,
        reporterIpHash,
      ],
      function (err) {
        if (err) {
          logger.error(`Report insert error: ${err.message}`);
          return resolve(res.status(500).json({ success: false, error: "Failed to save report." }));
        }

        // Check and update hotspot clusters asynchronously
        updateHotspots(db, parseFloat(latitude), parseFloat(longitude));

        logger.info(`New report submitted: ${reportId} | category: ${waste_category} | risk: ${riskScore}`);

        resolve(res.status(201).json({
          success: true,
          data: {
            id: reportId,
            status: "pending",
            risk_score: riskScore,
            message: "Report submitted successfully. Thank you for helping keep your city clean!",
          },
        }));
      }
    );
  });
}

// ─────────────────────────────────────────────
// GET ALL REPORTS (with optional filters)
// ─────────────────────────────────────────────
async function getReports(req, res) {
  const db = getDb();
  const { status, waste_category, limit = 50, offset = 0 } = req.query;

  let query = "SELECT id, latitude, longitude, waste_category, confidence_score, risk_score, status, is_hotspot, created_at, updated_at FROM reports WHERE 1=1";
  const params = [];

  // Safe parameterized filtering
  if (status) {
    query += " AND status = ?";
    params.push(status);
  }
  if (waste_category) {
    query += " AND waste_category = ?";
    params.push(waste_category);
  }

  query += " ORDER BY risk_score DESC, created_at DESC LIMIT ? OFFSET ?";
  params.push(parseInt(limit), parseInt(offset));

  db.all(query, params, (err, rows) => {
    if (err) {
      logger.error(`Get reports error: ${err.message}`);
      return res.status(500).json({ success: false, error: "Failed to retrieve reports." });
    }
    res.json({ success: true, count: rows.length, data: rows });
  });
}

// ─────────────────────────────────────────────
// GET SINGLE REPORT
// ─────────────────────────────────────────────
async function getReport(req, res) {
  const db = getDb();
  const { id } = req.params;

  // id is validated as UUID by middleware — safe to use in parameterized query
  db.get(
    "SELECT id, latitude, longitude, waste_category, confidence_score, risk_score, status, description, is_hotspot, created_at, updated_at FROM reports WHERE id = ?",
    [id],
    (err, row) => {
      if (err) {
        logger.error(`Get report error: ${err.message}`);
        return res.status(500).json({ success: false, error: "Failed to retrieve report." });
      }
      if (!row) return res.status(404).json({ success: false, error: "Report not found." });
      res.json({ success: true, data: row });
    }
  );
}

// ─────────────────────────────────────────────
// UPDATE REPORT STATUS (admin only)
// ─────────────────────────────────────────────
async function updateReportStatus(req, res) {
  const db = getDb();
  const { id } = req.params;
  const { status } = req.body;

  db.run(
    "UPDATE reports SET status = ?, updated_at = CURRENT_TIMESTAMP, updated_by = ? WHERE id = ?",
    [status, req.user.id, id],
    function (err) {
      if (err) {
        logger.error(`Update report error: ${err.message}`);
        return res.status(500).json({ success: false, error: "Failed to update report." });
      }
      if (this.changes === 0) {
        return res.status(404).json({ success: false, error: "Report not found." });
      }

      logger.info(`Report ${id} status updated to "${status}" by admin ${req.user.id}`);
      res.json({ success: true, data: { id, status, updated_at: new Date().toISOString() } });
    }
  );
}

// ─────────────────────────────────────────────
// GET HOTSPOT CLUSTERS
// ─────────────────────────────────────────────
async function getHotspots(req, res) {
  const db = getDb();

  db.all(
    "SELECT * FROM hotspots ORDER BY report_count DESC",
    [],
    (err, rows) => {
      if (err) {
        logger.error(`Get hotspots error: ${err.message}`);
        return res.status(500).json({ success: false, error: "Failed to retrieve hotspots." });
      }
      res.json({ success: true, count: rows.length, data: rows });
    }
  );
}

// ─────────────────────────────────────────────
// DASHBOARD STATS (admin)
// ─────────────────────────────────────────────
async function getDashboardStats(req, res) {
  const db = getDb();

  const queries = {
    total: "SELECT COUNT(*) as count FROM reports",
    byStatus: "SELECT status, COUNT(*) as count FROM reports GROUP BY status",
    byCategory: "SELECT waste_category, COUNT(*) as count FROM reports GROUP BY waste_category",
    hotspots: "SELECT COUNT(*) as count FROM hotspots WHERE risk_level IN ('high','critical')",
  };

  const stats = {};

  db.get(queries.total, [], (err, row) => {
    stats.totalReports = row?.count || 0;

    db.all(queries.byStatus, [], (err, rows) => {
      stats.byStatus = rows || [];

      db.all(queries.byCategory, [], (err, rows) => {
        stats.byCategory = rows || [];

        db.get(queries.hotspots, [], (err, row) => {
          stats.criticalHotspots = row?.count || 0;
          res.json({ success: true, data: stats });
        });
      });
    });
  });
}

// ─────────────────────────────────────────────
// INTERNAL HELPERS
// ─────────────────────────────────────────────

/**
 * Calculate a risk score (0–100) based on:
 * - Number of nearby reports within 200m radius
 * Higher count = higher risk
 */
function calculateRiskScore(db, lat, lng) {
  return new Promise((resolve) => {
    // Approximate degree offset for 200m (~0.0018 degrees)
    const offset = 0.0018;
    db.get(
      `SELECT COUNT(*) as nearby
       FROM reports
       WHERE latitude BETWEEN ? AND ?
         AND longitude BETWEEN ? AND ?
         AND status != 'cleaned'`,
      [lat - offset, lat + offset, lng - offset, lng + offset],
      (err, row) => {
        if (err || !row) return resolve(0);
        const nearby = row.nearby || 0;
        // Base score + bonus for clustering
        const score = Math.min(100, 20 + nearby * 15);
        resolve(score);
      }
    );
  });
}

/**
 * Update or create hotspot clusters for nearby report groupings
 */
function updateHotspots(db, lat, lng) {
  const offset = 0.0018;

  db.get(
    `SELECT COUNT(*) as count FROM reports
     WHERE latitude BETWEEN ? AND ?
       AND longitude BETWEEN ? AND ?
       AND status != 'cleaned'`,
    [lat - offset, lat + offset, lng - offset, lng + offset],
    (err, row) => {
      if (err || !row) return;
      const count = row.count;

      if (count < 3) return; // Only flag as hotspot with 3+ reports

      const riskLevel = count >= 10 ? "critical" : count >= 7 ? "high" : count >= 5 ? "medium" : "low";

      // Check for existing hotspot in area
      db.get(
        "SELECT id FROM hotspots WHERE center_lat BETWEEN ? AND ? AND center_lng BETWEEN ? AND ?",
        [lat - offset, lat + offset, lng - offset, lng + offset],
        (err, existing) => {
          if (existing) {
            db.run(
              "UPDATE hotspots SET report_count = ?, risk_level = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
              [count, riskLevel, existing.id]
            );
          } else {
            db.run(
              "INSERT INTO hotspots (id, center_lat, center_lng, report_count, risk_level) VALUES (?, ?, ?, ?, ?)",
              [uuidv4(), lat, lng, count, riskLevel]
            );
          }

          // Mark individual reports in this cluster as hotspot
          db.run(
            `UPDATE reports SET is_hotspot = 1
             WHERE latitude BETWEEN ? AND ?
               AND longitude BETWEEN ? AND ?`,
            [lat - offset, lat + offset, lng - offset, lng + offset]
          );
        }
      );
    }
  );
}

module.exports = {
  submitReport,
  getReports,
  getReport,
  updateReportStatus,
  getHotspots,
  getDashboardStats,
};
