import "dotenv/config";

function getEnvVar(name, required = true) {
  const value = process.env[name];
  if (!value && required) {
    throw new Error(
      `Environment variable "${name}" is required but not defined.`
    );
  }
  return value;
}

export const PORT = parseInt(getEnvVar("PORT"));
export const NODE_ENV = parseInt(getEnvVar("NODE_ENV"));
export const DATABASE_URL = getEnvVar("DATABASE_URL");
export const JWT_SECRET = getEnvVar("JWT_SECRET");
export const ACCESS_TOKEN_SECRET = getEnvVar("ACCESS_TOKEN_SECRET");
export const REFRESH_TOKEN_SECRET = getEnvVar("REFRESH_TOKEN_SECRET");

export const UPSTASH_REDIS_REST_URL = getEnvVar("UPSTASH_REDIS_REST_URL");
export const UPSTASH_REDIS_REST_TOKEN = getEnvVar("UPSTASH_REDIS_REST_TOKEN");

export const SMTP_SERVER_HOST = getEnvVar("SMTP_SERVER_HOST");
export const SMTP_PORT = getEnvVar("SMTP_PORT");
export const SMTP_USER_LOGIN = getEnvVar("SMTP_USER_LOGIN");
export const SMTP_PASSWORD = getEnvVar("SMTP_PASSWORD");

export const FORM_EMAIL = getEnvVar("FORM_EMAIL");
export const BASE_URL = getEnvVar("BASE_URL");
export const BASE_URL_PROD = getEnvVar("BASE_URL_PROD");
