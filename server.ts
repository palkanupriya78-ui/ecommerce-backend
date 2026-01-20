import app from "./src/app";
import logger from "./src/utils/logger";
import { port } from "./src/config";
import { connectDB, disconnectDB } from "./src/config/db";
import type { Server } from "http";

async function start() {
  await connectDB(process.env.MONGO_URI as string);

  const server: Server = app.listen(port, () => {
    logger.info(`Server running on port ${port}`);
  });

  const shutdown = async (signal: string) => {
    logger.warn(`${signal} received. Shutting down...`);
    server.close(async () => {
      try {
        await disconnectDB();
      } finally {
        logger.info("Shutdown complete");
        process.exit(0);
      }
    });
  };

  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));

  process.on("unhandledRejection", (reason: unknown) => {
    logger.error({ reason }, "unhandledRejection");
    server.close(() => process.exit(1));
  });

  process.on("uncaughtException", (err: unknown) => {
    logger.error({ err }, "uncaughtException");
    process.exit(1);
  });
}

start().catch((err: unknown) => {
  logger.error({ err }, "Failed to start server");
  process.exit(1);
});
