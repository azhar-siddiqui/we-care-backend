import jwt from "jsonwebtoken";
import { asyncHandler } from "../../helper/async.handler.js";

import { ACCESS_TOKEN_SECRET } from "../../config/dotenv.config.js";
import { AuthenticationError } from "../error-handler/index.js";
import { redis } from "../../utils/redis.connection.js";

export const authenticateAdmin = asyncHandler(async (req, resp, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(" ")[1]; // Expecting "Bearer <token>"

  if (!token) {
    throw new AuthenticationError("No access token provided");
  }

  try {
    const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET);
    req.admin = decoded; // Attach decoded token data to request

    // Optional: Verify if the user still has an active session in Redis
    const refreshToken = req.cookies?.refreshToken;
    if (refreshToken) {
      const storedToken = await redis.get(
        `refresh_token:${decoded.id}:${refreshToken}`
      );
      if (!storedToken) {
        throw new AuthenticationError("Invalid session. Please log in again.");
      }
    }

    next();
  } catch (error) {
    console.log("error:==", error);
    if (error.name === "TokenExpiredError") {
      throw new AuthenticationError("Access token expired");
    }
    throw new AuthenticationError("Invalid access token");
  }
});
