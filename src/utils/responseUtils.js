// Utility function for success responses
export const sendSuccessResponse = (
  res,
  statusCode,
  message,
  data = null,
  metadata = {}
) => {
  res.status(statusCode).json({
    success: true,
    message,
    data,
    ...metadata, // Optional metadata like pagination, timestamps, etc.
  });
};

export const sendErrorResponse = (res, statusCode, message) => {
  res.status(statusCode).json({
    success: false,
    message,
  });
};
