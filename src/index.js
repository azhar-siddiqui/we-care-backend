import express from "express";
import { PORT } from "./config/dotenv.config.js";
import { HttpStatusCode } from "./utils/http.statuscodes.js";
import cors from "cors";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import { errorMiddleware } from "./middleware/error-handler/error.middleware.js";
import routes from "./routes/index.js";

const app = express();

// CORS configuration
app.use(
  cors({
    origin: ["http://localhost:5173", "http://localhost:5174"],
    allowedHeaders: ["Authrization", "Content-Type"],
    credentials: true,
  })
);

// Body parsers and cookie parser
app.use(express.json({ limit: "100mb" }));
app.use(express.urlencoded({ limit: "100mb", extended: true }));
app.use(cookieParser());

// Trust proxy for rate limiting
app.set("trust proxy", 1);

app.use(helmet());

// API Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: (req) => (req.user ? 1000 : 100),
  standardHeaders: true,
  legacyHeaders: true,
  message: {
    status: 429,
    message: "Too many requests. Please try again later.",
  },
  keyGenerator: (req) => req.ip,
});

// Apply the rate limiter to all requests
app.use(limiter);

app.use(routes);

app.get("/", (req, resp) => {
  return resp.status(HttpStatusCode.OK).json({
    message: "App is perfectly working",
  });
});

app.use(errorMiddleware);

// const server = app.listen(PORT, () =>
const server = app.listen(PORT, () =>
  console.log(`Server is running on http://localhost:${PORT}/api`)
);

server.on("error", (err) => {
  console.log(`Server Error: ${err}`);
});
