const swaggerDefinition = {
  openapi: "3.0.0",
  info: {
    title: "WeCare API",
    version: "1.0.0",
    description:
      "API documentation for the WeCare application admin authentication endpoints.",
  },
  servers: [
    {
      url: "http://localhost:3000/api",
      description: "Local development server",
    },
  ],
  components: {
    securitySchemes: {
      BearerAuth: {
        type: "http",
        scheme: "bearer",
        bearerFormat: "JWT",
      },
      CookieAuth: {
        type: "apiKey",
        in: "cookie",
        name: "refreshToken",
      },
    },
    schemas: {
      RegisterAdminRequest: {
        type: "object",
        required: [
          "labName",
          "ownerName",
          "email",
          "password",
          "contactNumber",
        ],
        properties: {
          labName: { type: "string", description: "Name of the lab" },
          ownerName: { type: "string", description: "Name of the lab owner" },
          email: {
            type: "string",
            format: "email",
            description: "Admin email address",
          },
          password: {
            type: "string",
            format: "password",
            description: "Admin password",
          },
          contactNumber: {
            type: "string",
            description: "Admin contact number",
          },
          previousSoftware: {
            type: "string",
            description: "Previous software used (optional)",
            nullable: true,
          },
        },
      },
      VerifyOtpRequest: {
        type: "object",
        required: ["email", "otp"],
        properties: {
          email: {
            type: "string",
            format: "email",
            description: "Admin email address",
          },
          otp: {
            type: "string",
            description: "One-time password sent to email",
          },
        },
      },
      LoginRequest: {
        type: "object",
        required: ["email", "password"],
        properties: {
          email: {
            type: "string",
            format: "email",
            description: "Admin email address",
          },
          password: {
            type: "string",
            format: "password",
            description: "Admin password",
          },
        },
      },
      RefreshTokenRequest: {
        type: "object",
        properties: {
          refreshToken: {
            type: "string",
            description: "Refresh token stored in cookie",
          },
        },
      },
      AdminResponse: {
        type: "object",
        properties: {
          id: { type: "string", description: "Admin ID" },
          labName: { type: "string", description: "Name of the lab" },
          ownerName: { type: "string", description: "Name of the lab owner" },
          email: {
            type: "string",
            format: "email",
            description: "Admin email address",
          },
          contactNumber: {
            type: "string",
            description: "Admin contact number",
          },
          createdAt: {
            type: "string",
            format: "date-time",
            description: "Account creation date",
          },
          updatedAt: {
            type: "string",
            format: "date-time",
            description: "Account last updated date",
          },
        },
      },
      LoginResponse: {
        type: "object",
        properties: {
          success: { type: "boolean", example: true },
          message: { type: "string", example: "Admin logged in successfully" },
          data: {
            type: "object",
            properties: {
              admin: { $ref: "#/components/schemas/AdminResponse" },
              accessToken: { type: "string", description: "JWT access token" },
            },
          },
        },
      },
      RefreshTokenResponse: {
        type: "object",
        properties: {
          success: { type: "boolean", example: true },
          message: { type: "string", example: "Token refreshed successfully" },
          data: {
            type: "object",
            properties: {
              accessToken: {
                type: "string",
                description: "New JWT access token",
              },
            },
          },
        },
      },
      LogoutResponse: {
        type: "object",
        properties: {
          success: { type: "boolean", example: true },
          message: { type: "string", example: "Logged out successfully" },
        },
      },
      ErrorResponse: {
        type: "object",
        properties: {
          success: { type: "boolean", example: false },
          message: { type: "string", description: "Error message" },
        },
      },
    },
  },
};

export default swaggerDefinition;
