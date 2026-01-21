const { z } = require("zod");

const registerSchema = z.object({
  body: z.object({
    name: z.string().min(2),
    email: z.string().email(),
    password: z.string().min(6),
  }),
});

const loginSchema = z.object({
  body: z.object({
    email: z.string().email(),
    password: z.string().min(6),
  }),
});

const adminCreateUserSchema = z.object({
  body: z.object({
    name: z.string().min(2),
    email: z.string().email(),
    password: z.string().min(6),
    role: z.enum(["user", "admin"]).default("user"),
  }),
});

// Step 1: request otp
const forgotPasswordRequestOtpSchema = z.object({
  body: z.object({
    email: z.string().email(),
  }),
});

// Step 2: verify otp
const forgotPasswordVerifyOtpSchema = z.object({
  body: z.object({
    email: z.string().email(),
    otp: z
      .string()
      .trim()
      .regex(/^\d{6}$/, "OTP must be a 6-digit number"),
  }),
});

// Step 3: reset password (token comes from Authorization header)
const forgotPasswordOtpResetSchema = z.object({
  body: z
    .object({
      newPassword: z.string().min(6),
      confirmPassword: z.string().min(6),
    })
    .refine((data) => data.newPassword === data.confirmPassword, {
      message: "Passwords do not match",
      path: ["confirmPassword"],
    }),
});




module.exports = { registerSchema, loginSchema,adminCreateUserSchema, forgotPasswordRequestOtpSchema,
  forgotPasswordVerifyOtpSchema,
  forgotPasswordOtpResetSchema,};
