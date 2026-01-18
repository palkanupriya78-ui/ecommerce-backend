const pino = require("pino");
const fs = require("fs");
const path = require("path");
const { env, logLevel } = require("../config");

const logDir = path.join(process.cwd(), "logs");
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir);

function dateKey() {
  return new Date().toISOString().slice(0, 10);
}

const appLogPath = () => path.join(logDir, `app-${dateKey()}.log`);
const errLogPath = () => path.join(logDir, `error-${dateKey()}.log`);

const streams = [
  { level: "info", stream: fs.createWriteStream(appLogPath(), { flags: "a" }) },
  { level: "error", stream: fs.createWriteStream(errLogPath(), { flags: "a" }) },
];

const isProd = env === "production";

const multi = pino.multistream(
  [
    ...streams,
    !isProd && {
      stream: pino.transport({
        target: "pino-pretty",
        options: { translateTime: "SYS:standard", ignore: "pid,hostname" },
      }),
    },
  ].filter(Boolean)
);

const logger = pino({ level: logLevel }, multi);

module.exports = logger;
