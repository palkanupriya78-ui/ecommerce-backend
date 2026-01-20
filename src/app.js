const express = require("express");
const requestLogger = require("./middlewares/requestLogger");
const notFound = require("./middlewares/notFound");
const errorHandler = require("./middlewares/errorHandler");
const v1Routes = require("./routes");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const { API_V1, ROOT_MESSAGE } = require("../src/constant/appConfig")

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: true,            // later set frontend url
    credentials: true,       // IMPORTANT for cookies
  })
);
app.use(requestLogger);

app.get("/", (req, res) => res.send(ROOT_MESSAGE));

app.use(API_V1, v1Routes);

app.use(notFound);
app.use(errorHandler);

module.exports = app;
