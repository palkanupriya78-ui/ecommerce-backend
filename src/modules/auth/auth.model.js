const mongoose = require("mongoose");
const { USER, ADMIN } = require("../../constant/roles");

const passwordResetOtpSchema = new mongoose.Schema(
  {
    otpHash: { type: String, select: false },
    expiresAt: { type: Date },
    attempts: { type: Number, default: 0 },
    verifiedAt: { type: Date, default: null },
    usedAt: { type: Date, default: null },
  },
  { _id: false }
);

const passwordResetSessionSchema = new mongoose.Schema(
  {
    tokenHash: { type: String, select: false },
    expiresAt: { type: Date },
    usedAt: { type: Date, default: null },
  },
  { _id: false }
);

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true, minlength: 6, select: false, trim: true },
    role: { type: String, enum: [USER, ADMIN], default: USER },
    profilePhoto: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "File",
      default: null,
    },
    refreshTokenHash: { type: String, select: false },
    resetPasswordTokenHash: { type: String },
    resetPasswordExpiresAt: { type: Date },
    passwordResetOtp: { type: passwordResetOtpSchema, default: null },
    passwordResetSession: { type: passwordResetSessionSchema, default: null },
    passwordChangedAt: { type: Date },
  },
  { timestamps: true }
);

module.exports = mongoose.model(USER, userSchema);
