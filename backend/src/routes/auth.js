// src/routes/auth.js
const express = require("express");
const router = express.Router();

const { authLimiter } = require("../middleware/security");
const { validateLogin } = require("../middleware/validation");
const { authenticate } = require("../middleware/auth");
const { login, getProfile } = require("../controllers/authController");

router.post("/login", authLimiter, validateLogin, login);
router.get("/profile", authenticate, getProfile);

module.exports = router;
