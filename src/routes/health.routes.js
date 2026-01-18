const express = require("express");
const router = express.Router();
const { dbReady } = require("../config/db");

router.get("/health", (req, res) => {
  res.json({
    success: true,
    status: "ok",
    uptimeSec: Math.floor(process.uptime()),
    reqId: req.reqId,
  });
});

// ready = dependencies ready? (DB etc.)
router.get("/ready", (req, res) => {
  const ready = dbReady();
  res.status(ready ? 200 : 503).json({
    success: ready,
    status: ready ? "ready" : "not_ready",
    db: ready ? "connected" : "disconnected",
    reqId: req.reqId,
  });
});

module.exports = router;
