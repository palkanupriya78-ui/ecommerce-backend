const logger = require("../utils/logger");
const { env } = require("../config");

module.exports = function errorHandler(err, req, res, next) {
  const statusCode = err.statusCode || 500;

  // Logging (never log secrets / tokens / passwords)
  logger.error(
    {
      reqId: req.reqId,
      method: req.method,
      url: req.originalUrl,
      statusCode,
      err: {
        name: err.name,
        message: err.message,
        stack: env === "production" ? undefined : err.stack,
      },
    },
    "api_error"
  );

  // Client response
  res.status(statusCode).json({
    success: false,
    message: err.message || "Internal Server Error",
    reqId: req.reqId,
    ...(env !== "production" ? { stack: err.stack } : {}),
  });
};
