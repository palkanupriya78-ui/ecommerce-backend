const express = require("express");
const asyncHandler = require("../utils/asyncHandler");
const AppError = require("../utils/AppError");

const router = express.Router();

router.get("/ok", (req, res) => {
  res.json({ success: true, message: "Everything is fine" });
});

router.get("/sync-error", (req, res) => {
  throw new AppError("This is a SYNC error", 400);
});

router.get(
  "/async-error",
  asyncHandler(async (req, res) => {
    // simulate async failure
    throw new AppError("This is an ASYNC error", 500);
  })
);

module.exports = router;
