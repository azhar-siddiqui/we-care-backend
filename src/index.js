import express from "express";
import { PORT } from "./config/dotenv.config.js";
import { HttpStatusCode } from "./utils/http.statuscodes.js";
import cors from "cors";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import { errorMiddleware } from "./middleware/error-handler/error.middleware.js";
import routes from "./routes/index.js";
import swaggerUi from "swagger-ui-express";
import YAML from "yamljs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Load Swagger YAML
const swaggerDocument = YAML.load(path.join(__dirname, "./docs/swagger.yaml"));

// CORS configuration
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "http://localhost:5174",
      "https://we-care-backend-tiyp.onrender.com",
    ],
    allowedHeaders: ["Authorization", "Content-Type"],
    credentials: true,
  })
);

// Body parsers and cookie parser
app.use(express.json({ limit: "100mb" }));
app.use(express.urlencoded({ limit: "100mb", extended: true }));
app.use(cookieParser());

// Trust proxy for rate limiting
app.set("trust proxy", 1);

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'", // Required for Swagger UI scripts
          "https://we-care-backend-tiyp.onrender.com", // Allow scripts from your backend
        ],
        styleSrc: [
          "'self'",
          "'unsafe-inline'", // Required for Swagger UI styles
        ],
        connectSrc: [
          "'self'",
          "https://we-care-backend-tiyp.onrender.com", // Allow API calls to your backend
        ],
        imgSrc: ["'self'", "data:"], // Allow images (Swagger UI may use data URLs)
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [], // Ensure HTTPS is enforced
      },
    },
  })
);

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

// Serve Swagger UI at /api-docs
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocument));

app.use(routes);

app.get("/", (req, resp) => {
  return resp.status(HttpStatusCode.OK).json({
    message: "App is perfectly working",
  });
});

app.use(errorMiddleware);

// const server = app.listen(PORT, () =>
const server = app.listen(PORT, () =>
  console.log(`Server is running on http://localhost:${PORT}`)
);

server.on("error", (err) => {
  console.log(`Server Error: ${err}`);
});
