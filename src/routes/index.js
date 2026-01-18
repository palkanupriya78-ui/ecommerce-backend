const express = require("express");
const router = express.Router();

const demoRoutes = require("./demo.routes");
const healthRoutes = require("./health.routes");
const docsRoutes = require("./docs.routes");

router.use("/health", healthRoutes);
router.use("/docs", docsRoutes);
router.use("/demo", demoRoutes);

module.exports = router;
