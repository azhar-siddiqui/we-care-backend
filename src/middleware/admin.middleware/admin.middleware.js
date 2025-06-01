import jwt from "jsonwebtoken";
import { asyncHandler } from "../../helper/async.handler.js";
import { AuthenticationError } from "../error-handler.js";
import { ACCESS_TOKEN_SECRET } from "../../config/dotenv.config.js";

export const authenticateAdmin = asyncHandler(async (req, resp, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(" ")[1]; // Expecting "Bearer <token>"

  if (!token) {
    throw new AuthenticationError("No access token provided");
  }

  const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET);
  req.admin = decoded; // Attach decoded token data to request
  next();
});
