require("dotenv").config();
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const{ADMIN_IS_ALREADY_EXIST,ADMIN,ADMIN_EMAIL_AND_PASSWORD_IS_MISSING_IN_ENV}=require("../src/constant/messages")
const User = require("../src/modules/auth/auth.model");
const { connectDB, disconnectDB } = require("../src/config/db");

async function createAdmin() {
  await connectDB(process.env.MONGO_URI);

  const email = process.env.ADMIN_EMAIL;
  const password = process.env.ADMIN_PASSWORD;

  if (!email || !password) {
    throw new Error(ADMIN_EMAIL_AND_PASSWORD_IS_MISSING_IN_ENV);
  }

  const existing = await User.findOne({ email });
  if (existing) {
    console.log(ADMIN_IS_ALREADY_EXIST, email);
    await disconnectDB();
    process.exit(0);
  }

  const passwordHash = await bcrypt.hash(password, 10);
  await User.create({
    name: process.env.ADMIN_NAME || ADMIN,
    email,
    password: passwordHash,
    role: ADMIN,
  });
  await disconnectDB();
  process.exit(0);
}

createAdmin().catch(async (e) => {
  console.error(FAILED, e.message);
  try {
    await disconnectDB();
  } catch {
    try { await mongoose.disconnect(); } catch {}
  }
  process.exit(1);
});
