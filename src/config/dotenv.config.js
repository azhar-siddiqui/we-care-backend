import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Get the project root directory (two levels up from src/config)
const rootDir = path.resolve(__dirname, "../../");

// Determine the environment (default to "development")
const env = process.env.NODE_ENV || "development";

// Map NODE_ENV to the corresponding .env file in the project root
const envFiles = {
  development: path.join(rootDir, ".env.dev"),
  production: path.join(rootDir, ".env.prod"),
  test: path.join(rootDir, ".env.test"),
};

// Load the default .env file from the project root (optional, for shared variables)
const defaultEnvConfig = dotenv.config({ path: path.join(rootDir, ".env") });
if (defaultEnvConfig.error && !defaultEnvConfig.error.code.includes("ENOENT")) {
  console.warn(
    `Warning: Failed to load default .env file: ${defaultEnvConfig.error.message}`
  );
}

// Load the environment-specific file (e.g., .env.dev, .env.prod) from the project root
const envFile = envFiles[env] || envFiles.development;
const envConfig = dotenv.config({ path: envFile });
if (envConfig.error) {
  throw new Error(
    `Failed to load environment file "${envFile}": ${envConfig.error.message}`
  );
}

// Function to get environment variables with validation
function getEnvVar(name, required = true, defaultValue = null) {
  const value = process.env[name] || defaultValue;

  if (!value && required) {
    throw new Error(
      `Environment variable "${name}" is required but not defined.`
    );
  }
  return value;
}

// Export environment variables
export const PORT = parseInt(getEnvVar("PORT"));
export const NODE_ENV = getEnvVar("NODE_ENV");
export const DATABASE_URL = getEnvVar("DATABASE_URL");
export const JWT_SECRET = getEnvVar("JWT_SECRET");
export const ACCESS_TOKEN_SECRET = getEnvVar("ACCESS_TOKEN_SECRET");
export const REFRESH_TOKEN_SECRET = getEnvVar("REFRESH_TOKEN_SECRET");
export const UPSTASH_REDIS_REST_URL = getEnvVar("UPSTASH_REDIS_REST_URL");
export const UPSTASH_REDIS_REST_TOKEN = getEnvVar("UPSTASH_REDIS_REST_TOKEN");
export const SMTP_SERVER_HOST = getEnvVar("SMTP_SERVER_HOST");
export const SMTP_PORT = parseInt(getEnvVar("SMTP_PORT"));
export const SMTP_USER_LOGIN = getEnvVar("SMTP_USER_LOGIN");
export const SMTP_PASSWORD = getEnvVar("SMTP_PASSWORD");
export const FORM_EMAIL = getEnvVar("FORM_EMAIL");
export const BASE_URL = getEnvVar("BASE_URL");
