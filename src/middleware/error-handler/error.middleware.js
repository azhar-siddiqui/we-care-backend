import { AppError } from "./index.js";

export const errorMiddleware = (error, req, resp, next) => {
  if (error instanceof AppError) {
    console.log(`Error ${req.method} ${req.url} - ${error.message}`);
    return resp.status(error.statusCode).json({
      status: "error",
      message: error.message,
      ...(error.details && { details: error.details }),
    });
  }

  // Handle unexpected errors
  console.error(`Unhandled error ${req.method} ${req.url} - ${error.message}`);
  return resp.status(500).json({
    status: "error",
    message: "Something went wrong, please try again",
  });
};
