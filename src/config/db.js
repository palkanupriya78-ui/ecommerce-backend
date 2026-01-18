const mongoose = require("mongoose");
const logger = require("../utils/logger");
const { env } = require("./index");

let isConnected = false;

async function connectDB(mongoUri) {
  if (!mongoUri) throw new Error("MONGO_URI is missing");

  mongoose.connection.on("connected", () => {
    isConnected = true;
    logger.info(" MongoDB connected");
  });

  mongoose.connection.on("disconnected", () => {
    isConnected = false;
    logger.warn("⚠️ MongoDB disconnected");
  });

  mongoose.connection.on("error", (err) => {
    isConnected = false;
    logger.error({ err }, "MongoDB connection error");
  });

  await mongoose.connect(mongoUri, {
    autoIndex: env !== "production",
  });

  return mongoose;
}

async function disconnectDB() {
  try {
    await mongoose.disconnect();
  } catch (err) {
    logger.error({ err }, "Error while disconnecting DB");
  }
}

function dbReady() {
  return isConnected && mongoose.connection.readyState === 1;
}

module.exports = { connectDB, disconnectDB, dbReady };
