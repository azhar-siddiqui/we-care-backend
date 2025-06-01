export const HttpStatusCode = {
  // 1xx Informational
  CONTINUE: 100,
  SWITCHING_PROTOCOLS: 101,

  // 2xx Success
  OK: 200,
  CREATED: 201,
  ACCEPTED: 202,
  NO_CONTENT: 204,

  // 3xx Redirection
  MOVED_PERMANENTLY: 301,
  FOUND: 302,
  NOT_MODIFIED: 304,

  // 4xx Client Errors
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  METHOD_NOT_ALLOWED: 405,
  CONFLICT: 409,
  UNPROCESSABLE_ENTITY: 422,
  TOO_MANY_REQUESTS: 429,

  // 5xx Server Errors
  INTERNAL_SERVER_ERROR: 500,
  NOT_IMPLEMENTED: 501,
  BAD_GATEWAY: 502,
  SERVICE_UNAVAILABLE: 503,
  GATEWAY_TIMEOUT: 504,
};

export const HttpStatusMessage = {
  [HttpStatusCode.CONTINUE]: "Continue",
  [HttpStatusCode.SWITCHING_PROTOCOLS]: "Switching Protocols",

  [HttpStatusCode.OK]: "OK",
  [HttpStatusCode.CREATED]: "Created",
  [HttpStatusCode.ACCEPTED]: "Accepted",
  [HttpStatusCode.NO_CONTENT]: "No Content",

  [HttpStatusCode.MOVED_PERMANENTLY]: "Moved Permanently",
  [HttpStatusCode.FOUND]: "Found",
  [HttpStatusCode.NOT_MODIFIED]: "Not Modified",

  [HttpStatusCode.BAD_REQUEST]: "Bad Request",
  [HttpStatusCode.UNAUTHORIZED]: "Unauthorized",
  [HttpStatusCode.FORBIDDEN]: "Forbidden",
  [HttpStatusCode.NOT_FOUND]: "Not Found",
  [HttpStatusCode.METHOD_NOT_ALLOWED]: "Method Not Allowed",
  [HttpStatusCode.CONFLICT]: "Conflict",
  [HttpStatusCode.UNPROCESSABLE_ENTITY]: "Unprocessable Entity",
  [HttpStatusCode.TOO_MANY_REQUESTS]: "Too Many Requests",

  [HttpStatusCode.INTERNAL_SERVER_ERROR]: "Internal Server Error",
  [HttpStatusCode.NOT_IMPLEMENTED]: "Not Implemented",
  [HttpStatusCode.BAD_GATEWAY]: "Bad Gateway",
  [HttpStatusCode.SERVICE_UNAVAILABLE]: "Service Unavailable",
  [HttpStatusCode.GATEWAY_TIMEOUT]: "Gateway Timeout",
};
