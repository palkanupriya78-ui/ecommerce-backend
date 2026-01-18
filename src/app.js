const express = require("express");
const requestLogger = require("./middlewares/requestLogger");
const notFound = require("./middlewares/notFound");
const errorHandler = require("./middlewares/errorHandler");
const demoRoutes = require("./routes/demo.routes");
const v1Routes = require("./routes");
const app = express();
app.use(express.json());
app.use(requestLogger);

app.get("/", (req, res) => res.send("Logger + Error handling app running"));

app.use("/api/v1", v1Routes);

app.use(notFound);
app.use(errorHandler);

module.exports = app;
