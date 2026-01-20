import express, { Request, Response } from "express";
import cookieParser from "cookie-parser";
import cors from "cors";

import requestLogger from "./middlewares/requestLogger";
import notFound from "./middlewares/notFound";
import errorHandler from "./middlewares/errorHandler";
import v1Routes from "./routes";
import { API_V1, ROOT_MESSAGE } from "./constant/appConfig";

const app = express();

app.use(express.json());
app.use(cookieParser());

app.use(
  cors({
    origin: true, // later set frontend url
    credentials: true, // IMPORTANT for cookies
  })
);

app.use(requestLogger);

app.get("/", (_req: Request, res: Response) => res.send(ROOT_MESSAGE));

app.use(API_V1, v1Routes);

app.use(notFound);
app.use(errorHandler);

export default app;
