import rateLimit from "express-rate-limit";

export const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 5, // 5 attempts per 10 min per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: "For security reasons, your login is temporarily blocked due to multiple failed attempts. Please try again after 10 minutes." },
});

export const forgotPasswordLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: "Too many requests. Try again later." },
});
