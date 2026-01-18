const app = require("./src/app");
const logger = require("./src/utils/logger");
const { port } = require("./src/config");
const { connectDB, disconnectDB } = require("./src/config/db");

async function start() {
  await connectDB(process.env.MONGO_URI);

  const server = app.listen(port, () => {
    logger.info(`🚀 Server running on port ${port}`);
  });

  const shutdown = async (signal) => {
    logger.warn(`${signal} received. Shutting down...`);
    server.close(async () => {
      await disconnectDB();
      logger.info("✅ Shutdown complete");
      process.exit(0);
    });
  };

  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));

  process.on("unhandledRejection", (reason) => {
    logger.error({ reason }, "unhandledRejection");
    server.close(() => process.exit(1));
  });

  process.on("uncaughtException", (err) => {
    logger.error({ err }, "uncaughtException");
    process.exit(1);
  });
}

start().catch((err) => {
  logger.error({ err }, "Failed to start server");
  process.exit(1);
});
