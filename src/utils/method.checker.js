// Middleware to handle invalid methods
export const methodChecker = (allowedMethods) => {
  return (req, res, next) => {
    if (!allowedMethods.includes(req.method)) {
      return res.status(405).json({
        status: 405,
        error: `Method ${req.method} not allowed on ${req.path}`,
      });
    }
    next();
  };
};
