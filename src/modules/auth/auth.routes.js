const express = require("express");
const validate = require("../../middlewares/validate");
const { registerSchema, loginSchema ,adminCreateUserSchema,forgotPasswordRequestOtpSchema,forgotPasswordVerifyOtpSchema,forgotPasswordOtpResetSchema} = require("../auth/auth.schema");
const authController = require("../../modules/auth/auth.controller");
const { loginLimiter, forgotPasswordLimiter } = require("../../middlewares/rateLimiters");
const { protect,restrictTo } = require("../../middlewares/auth.middleware");
const {uploadProfile}=require("../../middlewares/profileUpload.middleware");
const router = express.Router();
router.post("/register",uploadProfile.single("profilePhoto"), validate(registerSchema), authController.register);
router.post("/login",loginLimiter, validate(loginSchema), authController.login);
router.post("/refresh", authController.refresh);
router.post("/logout",protect, authController.logout);
router.get("/me", protect, authController.me);
router.post(
    "/forgot-password/request-otp",
    forgotPasswordLimiter,
    validate(forgotPasswordRequestOtpSchema),
    authController.forgotPasswordRequestOtp
  );
  
  router.post(
    "/forgot-password/verify-otp",
    forgotPasswordLimiter,
    validate(forgotPasswordVerifyOtpSchema),
    authController.forgotPasswordVerifyOtp
  );
  
  router.post(
    "/forgot-password/reset",
    forgotPasswordLimiter,
    validate(forgotPasswordOtpResetSchema),
    authController.forgotPasswordReset
  );
  
router.post("/admin/create-user",protect,restrictTo("admin"),validate(adminCreateUserSchema),authController.adminCreateUser);

module.exports = router;
