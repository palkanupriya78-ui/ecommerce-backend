const express = require("express");
const validate = require("../../middlewares/validate");
const { registerSchema, loginSchema } = require("../auth/auth.schema");
const authController = require("../../modules/auth/auth.controller");
const { protect } = require("../../middlewares/auth.middleware");

const router = express.Router();

router.post("/register", validate(registerSchema), authController.register);
router.post("/login", validate(loginSchema), authController.login);
router.post("/refresh", authController.refresh);
router.post("/logout", authController.logout);
router.get("/me", protect, authController.me);

module.exports = router;
