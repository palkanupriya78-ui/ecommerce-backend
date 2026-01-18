const crypto = require("crypto");
const logger = require("../utils/logger");

module.exports = function requestLogger(req, res, next) {
  const reqId = req.headers["x-request-id"] || crypto.randomUUID();
  req.reqId = reqId;
  res.setHeader("x-request-id", reqId);

  const start = Date.now();

  res.on("finish", () => {
    logger.info(
      {
        reqId,
        method: req.method,
        url: req.originalUrl,
        statusCode: res.statusCode,
        durationMs: Date.now() - start,
      },
      "request"
    );
  });

  next();
};
