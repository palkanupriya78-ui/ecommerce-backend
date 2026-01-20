const express = require("express");
const validate = require("../../middlewares/validate");
const { registerSchema, loginSchema ,adminCreateUserSchema,forgotPasswordSchema,resetPasswordSchema,changePasswordSchema} = require("../auth/auth.schema");
const authController = require("../../modules/auth/auth.controller");
const { loginLimiter, forgotPasswordLimiter } = require("../../middlewares/rateLimiters");
const { protect,restrictTo } = require("../../middlewares/auth.middleware");
const router = express.Router();
router.post("/register", validate(registerSchema), authController.register);
router.post("/login",loginLimiter, validate(loginSchema), authController.login);
router.post("/refresh", authController.refresh);
router.post("/logout",protect, authController.logout);
router.get("/me", protect, authController.me);
router.post("/forgot-password",forgotPasswordLimiter, validate(forgotPasswordSchema), authController.forgotPassword);
router.post("/reset-password", validate(resetPasswordSchema), authController.resetPassword);
router.post("/change-password", protect, validate(changePasswordSchema), authController.changePassword);
router.post("/admin/create-user",protect,restrictTo("admin"),validate(adminCreateUserSchema),authController.adminCreateUser);

module.exports = router;
