const express = require("express");
const router = express.Router();
const { dbReady } = require("../config/db");
const {OK,SERVICE_TEMPORARY_UNAVAILABLE}=require("../constant/httpStatus")
router.get("/health", (req, res) => {
  res.json({
    success: true,
    status: "ok",
    uptimeSec: Math.floor(process.uptime()),
    reqId: req.reqId,
  });
});

router.get("/ready", (req, res) => {
  const ready = dbReady();
  res.status(ready ? OK : SERVICE_TEMPORARY_UNAVAILABLE).json({
    success: ready,
    status: ready ? "ready" : "not_ready",
    db: ready ? "connected" : "disconnected",
    reqId: req.reqId,
  });
});

module.exports = router;
