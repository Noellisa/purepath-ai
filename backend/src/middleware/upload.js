// src/middleware/upload.js
// Secure image upload handling with file type validation and sanitization

const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const sharp = require("sharp");
const logger = require("../utils/logger");

const UPLOAD_DIR = process.env.UPLOAD_DIR || "./uploads";
const MAX_FILE_SIZE = (parseInt(process.env.MAX_FILE_SIZE_MB) || 5) * 1024 * 1024;

// Ensure upload directory exists
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// ─────────────────────────────────────────────
// ALLOWED MIME TYPES (whitelist, not blacklist)
// ─────────────────────────────────────────────
const ALLOWED_MIME_TYPES = ["image/jpeg", "image/png", "image/webp"];
const ALLOWED_EXTENSIONS = [".jpg", ".jpeg", ".png", ".webp"];

// Magic bytes (file signatures) for true file type verification
const MAGIC_BYTES = {
  "image/jpeg": [[0xFF, 0xD8, 0xFF]],
  "image/png":  [[0x89, 0x50, 0x4E, 0x47]],
  "image/webp": [[0x52, 0x49, 0x46, 0x46]], // RIFF header
};

/**
 * Verify file magic bytes match claimed MIME type
 */
function verifyMagicBytes(buffer, mimeType) {
  const signatures = MAGIC_BYTES[mimeType];
  if (!signatures) return false;
  return signatures.some((sig) =>
    sig.every((byte, index) => buffer[index] === byte)
  );
}

// ─────────────────────────────────────────────
// MULTER CONFIGURATION (memory storage → process before saving)
// ─────────────────────────────────────────────
const upload = multer({
  storage: multer.memoryStorage(), // Keep in memory, validate before writing to disk

  limits: {
    fileSize: MAX_FILE_SIZE,
    files: 1,          // Only one file per request
    fields: 5,         // Limit form fields
    fieldNameSize: 50, // Limit field name length
  },

  fileFilter: (req, file, cb) => {
    // 1. Check MIME type (from Content-Type header)
    if (!ALLOWED_MIME_TYPES.includes(file.mimetype)) {
      logger.warn(`Upload rejected: invalid MIME type "${file.mimetype}" | requestId: ${req.requestId}`);
      return cb(new Error("Only JPEG, PNG, and WebP images are allowed"), false);
    }

    // 2. Check file extension
    const ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
      logger.warn(`Upload rejected: invalid extension "${ext}" | requestId: ${req.requestId}`);
      return cb(new Error("Invalid file extension"), false);
    }

    cb(null, true);
  },
});

// ─────────────────────────────────────────────
// POST-UPLOAD PROCESSING MIDDLEWARE
// Runs after multer: validates magic bytes, strips EXIF, re-encodes safely
// ─────────────────────────────────────────────
async function processUploadedImage(req, res, next) {
  if (!req.file) return next();

  const buffer = req.file.buffer;

  // 3. Verify magic bytes (defence against MIME spoofing)
  const isValidMagic = verifyMagicBytes(buffer, req.file.mimetype);
  if (!isValidMagic) {
    logger.warn(`Upload rejected: magic bytes mismatch for "${req.file.originalname}" | requestId: ${req.requestId}`);
    return res.status(400).json({
      success: false,
      error: "File content does not match declared image type.",
    });
  }

  try {
    // 4. Process with Sharp:
    //    - Strip all metadata (EXIF, GPS, ICC, etc.)
    //    - Re-encode to JPEG (neutralises polyglot file attacks)
    //    - Resize to max 1920×1080 (prevents huge file bombs)
    const processedBuffer = await sharp(buffer)
      .resize(1920, 1080, { fit: "inside", withoutEnlargement: true })
      .jpeg({ quality: 85, progressive: true })
      .withMetadata(false) // ← strips ALL EXIF/GPS metadata
      .toBuffer();

    // 5. Generate content hash (for deduplication & integrity)
    const imageHash = crypto
      .createHash("sha256")
      .update(processedBuffer)
      .digest("hex");

    // 6. Generate safe random filename (no user-controlled path segments)
    const safeFilename = `${crypto.randomUUID()}.jpg`;
    const savePath = path.join(UPLOAD_DIR, safeFilename);

    // 7. Write sanitized file to disk
    fs.writeFileSync(savePath, processedBuffer);

    // Attach processed file info to request
    req.file.processedPath = savePath;
    req.file.safeFilename = safeFilename;
    req.file.imageHash = imageHash;
    req.file.size = processedBuffer.length;

    logger.info(`Image processed and saved: ${safeFilename} (${req.file.size} bytes) | requestId: ${req.requestId}`);
    next();
  } catch (err) {
    logger.error(`Image processing error: ${err.message} | requestId: ${req.requestId}`);
    return res.status(400).json({
      success: false,
      error: "Image could not be processed. Please upload a valid image file.",
    });
  }
}

/**
 * Multer error handler
 */
function handleUploadError(err, req, res, next) {
  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(413).json({
        success: false,
        error: `File too large. Maximum size is ${process.env.MAX_FILE_SIZE_MB || 5}MB.`,
      });
    }
    return res.status(400).json({ success: false, error: err.message });
  }
  if (err) {
    return res.status(400).json({ success: false, error: err.message });
  }
  next();
}

module.exports = {
  upload: upload.single("image"),
  processUploadedImage,
  handleUploadError,
};
