export class AppError extends Error {
  constructor(message, statusCode, details, isOperational = true) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.details = details;
    Error.captureStackTrace(this, this.constructor);
  }
}

// Common error
export class NotFoundError extends AppError {
  constructor(message = "Resource not found") {
    super(message, 404);
  }
}

// Validation error (e.g. Joi, Zod, react-hook-form)
export class ValidationError extends AppError {
  constructor(message = "Invalid request data", details) {
    super(message, 400, details, true);
  }
}

// Authentication error
export class AuthenticationError extends AppError {
  constructor(message = "Unauthorize access") {
    super(message, 401);
  }
}

// Forbidden error (Insufficient permission)
export class ForbiddenError extends AppError {
  constructor(message = "Forbidden access") {
    super(message, 403);
  }
}

// Database error
export class DatabaseError extends AppError {
  constructor(message = "Database error", details) {
    super(message, 500, true, details);
  }
}

// Rate limit error
export class RateLimitError extends AppError {
  constructor(message = "Too many request, please try again later") {
    super(message, 429);
  }
}
