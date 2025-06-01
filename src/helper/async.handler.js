export const asyncHandler = (fn) => async (req, res, next) => {
  try {
    await fn(req, res, next);
  } catch (error) {
    next(error);
    // if (error.name === "ValidationError") {
    //   return sendErrorResponse(res, 400, error.message);
    // }
    // if (error.name === "UnauthorizedError") {
    //   return sendErrorResponse(res, 401, error.message);
    // }
    // if (error.name === "ForbiddenError") {
    //   return sendErrorResponse(res, 403, error.message);
    // }
    // if (error.name === "NotFoundError") {
    //   return sendErrorResponse(res, 404, error.message);
    // }

    // // Default error response
    // return sendErrorResponse(res, 500, "Internal server error");
  }
};
