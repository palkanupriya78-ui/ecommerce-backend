const express = require("express");
const router = express.Router();

const healthRoutes = require("./health.routes");
const docsRoutes = require("./docs.routes");
const authRoutes = require("../modules/auth/auth.routes");

router.use("/health", healthRoutes);
router.use("/docs", docsRoutes);
router.use("/auth", authRoutes);

module.exports = router;
