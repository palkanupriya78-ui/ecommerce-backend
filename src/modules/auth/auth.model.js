const mongoose = require("mongoose");
const {USER,ADMIN}=require("../../constant/roles")
const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true, minlength: 6, select: false },
    role: { type: String, enum: [USER, ADMIN], default: USER },
    refreshTokenHash: { type: String, select: false },
  },
  { timestamps: true }
);

module.exports = mongoose.model(USER, userSchema);
