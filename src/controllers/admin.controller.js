import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { v4 as uuidv4 } from "uuid";

import {
  loginSchema,
  registerAdminSchema,
  verifyOtpSchema,
} from "../validation/admin.auth.validation.js";

import prisma from "../config/db.js";
import { asyncHandler } from "../helper/async.handler.js";
import {
  sendErrorResponse,
  sendSuccessResponse,
} from "../utils/responseUtils.js";

import { generateOtp } from "../helper/generateOtp.js";
import { redis } from "../utils/redis.connection.js";
import { sendOtpEmail } from "../utils/sendOtpEmail.js";
import {
  ACCESS_TOKEN_SECRET,
  NODE_ENV,
  REFRESH_TOKEN_SECRET,
} from "../config/dotenv.config.js";
import {
  AuthenticationError,
  ValidationError,
} from "../middleware/error-handler/index.js";

export const registerAdmin = asyncHandler(async (req, resp) => {
  const validationResult = registerAdminSchema.safeParse(req.body);

  if (!validationResult.success) {
    const errors = validationResult.error.issues
      .map((issue) => issue.message)
      .join(", ");
    return sendErrorResponse(resp, 400, `Validation failed: ${errors}`);
  }

  const {
    labName,
    ownerName,
    email,
    password,
    contactNumber,
    previousSoftware,
  } = validationResult.data;

  if (!labName || !ownerName || !email || !password || !contactNumber) {
    return sendErrorResponse(
      resp,
      400,
      "All fields are required. Please provide  labName, ownerName, email, password, contactNumber and password"
    );
  }

  const isEmailExisted = await prisma.admin.findUnique({
    where: {
      email,
    },
  });

  if (isEmailExisted) {
    return sendErrorResponse(
      resp,
      400,
      "Email already exists. Please use a different email."
    );
  }

  // Generate OTP
  const otp = generateOtp();

  // Hash password
  const hashedPassword = await bcrypt.hash(password, 12);

  // Store admin data and OTP in Redis with 10-minute expiration
  const adminData = {
    labName,
    ownerName,
    email,
    password: hashedPassword,
    contactNumber,
    previousSoftware: previousSoftware || null,
    otp,
  };

  await redis.set(`admin:pending:${email}`, JSON.stringify(adminData), {
    ex: 600, // 10 minutes
  });

  // Send OTP email
  await sendOtpEmail(email, otp, ownerName);

  // Return success response
  return sendSuccessResponse(
    resp,
    200,
    "OTP sent to email. Please verify to complete registration.",
    { email }
  );
});

export const verifyAdminOtp = asyncHandler(async (req, resp) => {
  const validationResult = verifyOtpSchema.safeParse(req.body);

  if (!validationResult.success) {
    const errors = validationResult.error.issues
      .map((issue) => issue.message)
      .join(", ");
    return sendErrorResponse(resp, 400, `Validation failed: ${errors}`);
  }

  const { email, otp } = validationResult.data;

  // Retrieve admin data from Redis
  const adminData = await redis.get(`admin:pending:${email}`);
  if (!adminData) {
    return sendErrorResponse(resp, 400, "OTP expired or invalid email");
  }

  // Validate adminData structure
  if (
    typeof adminData !== "object" ||
    !adminData.labName ||
    !adminData.email ||
    !adminData.otp
  ) {
    return sendErrorResponse(
      resp,
      500,
      "Internal server error: Invalid data format"
    );
  }

  // Verify OTP
  if (adminData.otp !== otp) {
    return sendErrorResponse(resp, 400, "Invalid OTP");
  }

  // Check email uniqueness again
  const isEmailExisted = await prisma.admin.findUnique({
    where: { email },
  });

  if (isEmailExisted) {
    await redis.del(`admin:pending:${email}`);
    return sendErrorResponse(
      resp,
      400,
      "Email already exists. Please use a different email."
    );
  }

  // Save admin to database
  const newAdmin = await prisma.admin.create({
    data: {
      labName: adminData.labName,
      ownerName: adminData.ownerName,
      email: adminData.email,
      password: adminData.password,
      contactNumber: adminData.contactNumber,
      previousSoftware: adminData.previousSoftware,
    },
    select: {
      id: true,
      labName: true,
      ownerName: true,
      email: true,
      contactNumber: true,
      createdAt: true,
      updatedAt: true,
    },
  });

  // Delete from Redis
  await redis.del(`admin:pending:${email}`);

  return sendSuccessResponse(resp, 201, "Admin created successfully", newAdmin);
});

export const loginAdmin = asyncHandler(async (req, resp) => {
  // Validate the request body
  const validationResult = loginSchema.safeParse(req.body);

  if (!validationResult.success) {
    const errors = validationResult.error.issues
      .map((issue) => issue.message)
      .join(", ");
    throw new ValidationError(`Validation failed: ${errors}`);
  }

  const { email, password } = validationResult.data;

  // Check if admin exists
  const admin = await prisma.admin.findUnique({
    where: { email },
    select: {
      id: true,
      labName: true,
      ownerName: true,
      email: true,
      password: true,
      contactNumber: true,
      createdAt: true,
      updatedAt: true,
    },
  });

  if (!admin) {
    throw new AuthenticationError("Invalid email or password");
  }

  // Verify password
  const isPasswordValid = await bcrypt.compare(password, admin.password);
  if (!isPasswordValid) {
    throw new AuthenticationError("Invalid email or password");
  }

  // Generate access token (15 minutes)
  const accessToken = jwt.sign(
    { id: admin.id, email: admin.email, role: "admin" },
    ACCESS_TOKEN_SECRET,
    { expiresIn: "15m" }
  );

  // Generate refresh token
  const refreshToken = jwt.sign(
    { id: admin.id, email: admin.email, role: "admin", jti: uuidv4() },
    REFRESH_TOKEN_SECRET,
    { expiresIn: "7d" }
  );

  // Store refresh token in Redis
  await redis.set(
    `refresh_token:${admin.id}:${refreshToken}`,
    JSON.stringify({ userId: admin.id, email: admin.email }),
    { ex: 7 * 24 * 60 * 60 }
  );

  // Set refresh token in HTTP-only cookie
  resp.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: NODE_ENV == "production",
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: "/",
  });

  // Remove password from response
  const { password: _, ...adminWithoutPassword } = admin;

  // Return success response
  return resp.status(200).json({
    success: true,
    message: "Admin logged in successfully",
    data: { admin: adminWithoutPassword, accessToken },
  });
});

export const refreshAccessToken = asyncHandler(async (req, resp) => {
  const refreshToken = req.cookies?.refreshToken;

  if (!refreshToken) {
    throw new AuthenticationError("No refresh token provided");
  }

  // Verify refresh token
  const decoded = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);

  // Check if refresh token exists in Redis
  const storedToken = await redis.get(
    `refresh_token:${decoded.id}:${refreshToken}`
  );
  if (!storedToken) {
    throw new AuthenticationError("Invalid or expired refresh token");
  }

  // Generate new access token
  const newAccessToken = jwt.sign(
    { id: decoded.id, email: decoded.email, role: "admin" },
    ACCESS_TOKEN_SECRET,
    { expiresIn: "15m" }
  );

  // Rotate refresh token
  const newRefreshToken = jwt.sign(
    { id: decoded.id, email: decoded.email, role: "admin", jti: uuidv4() },
    REFRESH_TOKEN_SECRET,
    { expiresIn: "7d" }
  );

  // Update Redis
  await redis.del(`refresh_token:${decoded.id}:${refreshToken}`);
  await redis.set(
    `refresh_token:${decoded.id}:${newRefreshToken}`,
    JSON.stringify({ userId: decoded.id, email: decoded.email }),
    { ex: 7 * 24 * 60 * 60 }
  );

  // Set new refresh token in cookie
  resp.cookie("refreshToken", newRefreshToken, {
    httpOnly: true,
    secure: NODE_ENV == "production",
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: "/",
  });

  return resp.status(200).json({
    success: true,
    message: "Token refreshed successfully",
    data: { accessToken: newAccessToken },
  });
});

export const logoutAdmin = asyncHandler(async (req, resp) => {
  const refreshToken = req.cookies?.refreshToken;

  if (refreshToken) {
    const decoded = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);
    await redis.del(`refresh_token:${decoded.id}:${refreshToken}`);
  }

  // Clear the refresh token cookie
  resp.clearCookie("refreshToken", {
    httpOnly: true,
    secure: NODE_ENV == "production",
    sameSite: "strict",
    path: "/",
  });

  return resp.status(200).json({
    success: true,
    message: "Logged out successfully",
    data: null,
  });
});
