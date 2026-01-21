const crypto = require("crypto");

function hashToken(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function generateOtp() {
  // 6-digit numeric OTP
  return String(Math.floor(100000 + Math.random() * 900000));
}

function generateResetToken() {
  return crypto.randomBytes(32).toString("hex");
}

module.exports = { hashToken, generateOtp, generateResetToken };
