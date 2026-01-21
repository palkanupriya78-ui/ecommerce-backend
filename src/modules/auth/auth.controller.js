const asyncHandler = require("../../utils/asyncHandler");
const authService = require("../auth/auth.service");
const { OK, CREATED } = require("../../constant/httpStatus");

const register = asyncHandler(async (req, res) => {
  const { name, email, password } = req.validated.body;

  const { user, accessToken, refreshToken } = await authService.register({
    name,
    email,
    password,
    profilePhotoFile: req.file || null, 
  });

  res
    .cookie("refreshToken", refreshToken, authService.cookieOptions())
    .status(CREATED)
    .json({
      success: true,
      message: "Registered",
      data: { user, accessToken },
      reqId: req.reqId,
    });
});

const login = asyncHandler(async (req, res) => {
  const { email, password } = req.validated.body;
  const { user, accessToken, refreshToken } = await authService.login({
    email,
    password,
  });

  res
    .cookie("refreshToken", refreshToken, authService.cookieOptions())
    .status(OK)
    .json({
      success: true,
      message: "Logged in",
      data: { user, accessToken },
      reqId: req.reqId,
    });
});

const refresh = asyncHandler(async (req, res) => {
  const rt = req.cookies?.refreshToken;

  const { newAccessToken, newRefreshToken } = await authService.refresh(rt);

  res
    .cookie("refreshToken", newRefreshToken, authService.cookieOptions())
    .status(OK)
    .json({
      success: true,
      message: "Token refreshed",
      data: { accessToken: newAccessToken },
      reqId: req.reqId,
    });
});

const logout = asyncHandler(async (req, res) => {
  // ✅ revoke refresh token in DB (so cookie theft doesn't keep working)
  // req.user exists only if route is protected; handle both cases safely
  if (req.user?.id) {
    await authService.logout(req.user.id);
  }
  res
    .clearCookie("refreshToken", authService.cookieOptions())
    .status(OK)
    .json({ success: true, message: "Logged out", reqId: req.reqId });
});

const me = asyncHandler(async (req, res) => {
  res.status(OK).json({ success: true, data: req.user, reqId: req.reqId });
});

const adminCreateUser = asyncHandler(async (req, res) => {
  const result = await authService.adminCreateUser(req.validated?.body || req.body);

  res.status(CREATED).json({
    success: true,
    message: result.message,
    data: { user: result.user },
    reqId: req.reqId,
  });
});

/**
 * ✅ FORGOT PASSWORD (OTP FLOW)
 * Step 1: user enters email -> send OTP
 */
const forgotPasswordRequestOtp = asyncHandler(async (req, res) => {
  const { email } = req.validated?.body || req.body;

  const result = await authService.forgotPasswordRequestOtp({ email });

  // result.message should be generic: "If the email exists, an OTP has been sent."
  res.status(OK).json({
    success: true,
    message: result.message,
    reqId: req.reqId,
  });
});

/**
 * Step 2: user enters otp -> verify -> returns resetToken
 */
const forgotPasswordVerifyOtp = asyncHandler(async (req, res) => {
  const { email, otp } = req.validated?.body || req.body;

  const result = await authService.forgotPasswordVerifyOtp({ email, otp });

  res.status(OK).json({
    success: true,
    message: result.message || "OTP verified",
    data: { resetToken: result.resetToken, expiresInMinutes: result.expiresInMinutes },
    reqId: req.reqId,
  });
});

/**
 * Step 3: user sets new password using resetToken
 * Authorization: Bearer <resetToken>
 */
const forgotPasswordReset = asyncHandler(async (req, res) => {
  const auth = req.headers.authorization || "";
  const resetToken = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";

  const { newPassword, confirmPassword } = req.validated?.body || req.body;

  const result = await authService.forgotPasswordReset({
    resetToken,
    newPassword,
    confirmPassword,
  });

  res.status(OK).json({
    success: true,
    message: result.message || "Password reset successful",
    reqId: req.reqId,
  });
});

module.exports = {
  register,
  login,
  refresh,
  logout,
  me,
  adminCreateUser,
  forgotPasswordRequestOtp,
  forgotPasswordVerifyOtp,
  forgotPasswordReset,
};
