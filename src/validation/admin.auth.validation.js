import { z } from "zod";

export const ALLOWED_EMAIL_DOMAINS = [
  "gmail.com",
  "yahoo.com",
  "outlook.com",
  "aol.com",
  "icloud.com",
  "zoho.com",
  "proton.me",
  "yandex.ru",
];

export const registerAdminSchema = z.object({
  labName: z
    .string()
    .min(1, "Lab name is required")
    .max(191, "Lab name must not exceed 191 characters"),
  ownerName: z
    .string()
    .min(1, "Owner name is required")
    .max(191, "Owner name must not exceed 191 characters"),
  email: z
    .string()
    .email("Invalid email format")
    .max(191, "Email must not exceed 191 characters")
    .refine(
      (email) => {
        const domain = email.split("@")[1]?.toLowerCase();
        return domain && ALLOWED_EMAIL_DOMAINS.includes(domain);
      },
      {
        message: `Email domain must be one of: ${ALLOWED_EMAIL_DOMAINS.join(
          ", "
        )}`,
      }
    ),
  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .max(255, "Password must not exceed 255 characters"),
  contactNumber: z
    .string()
    .regex(/^\d+$/, "Contact number must contain only digits")
    .max(191, "Contact number must not exceed 191 characters"),
  previousSoftware: z
    .string()
    .max(191, "Previous software must not exceed 191 characters")
    .nullable()
    .optional(),
});

// Zod schema for OTP verification
export const verifyOtpSchema = z.object({
  email: z
    .string()
    .email("Invalid email format")
    .refine(
      (email) => {
        const domain = email.split("@")[1]?.toLowerCase();
        return domain && ALLOWED_EMAIL_DOMAINS.includes(domain);
      },
      {
        message: `Email domain must be one of: ${ALLOWED_EMAIL_DOMAINS.join(
          ", "
        )}`,
      }
    ),
  otp: z.string().regex(/^\d{5}$/, "OTP must be a 5-digit number"),
});

export const loginSchema = z.object({
  email: z
    .string()
    .email("Invalid email format")
    .max(191, "Email must not exceed 191 characters")
    .refine(
      (email) => {
        const domain = email.split("@")[1]?.toLowerCase();
        return domain && ALLOWED_EMAIL_DOMAINS.includes(domain);
      },
      {
        message: `Email domain must be one of: ${ALLOWED_EMAIL_DOMAINS.join(
          ", "
        )}`,
      }
    ),
  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .max(255, "Password must not exceed 255 characters"),
});
