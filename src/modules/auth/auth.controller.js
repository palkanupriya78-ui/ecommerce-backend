const asyncHandler = require("../../utils/asyncHandler");
const authService = require("../auth/auth.service");
const {OK,CREATED}=require("../../constant/httpStatus")
const register = asyncHandler(async (req, res) => {
  const { name, email, password } = req.validated.body;
  const { user, accessToken, refreshToken } = await authService.register({ name, email, password });
  res
    .cookie("refreshToken", refreshToken, authService.cookieOptions())
    .status(CREATED)
    .json({ success: true, message: "Registered", data: { user, accessToken }, reqId: req.reqId });
});

const login = asyncHandler(async (req, res) => {
  const { email, password } = req.validated.body;
  const { user, accessToken, refreshToken } = await authService.login({ email, password });

  res
    .cookie("refreshToken", refreshToken, authService.cookieOptions())
    .status(OK)
    .json({ success: true, message: "Logged in", data: { user, accessToken }, reqId: req.reqId });
});

const refresh = asyncHandler(async (req, res) => {
  const rt = req.cookies.refreshToken;
  const { newAccessToken, newRefreshToken } = await authService.refresh(rt);

  res
    .cookie("refreshToken", newRefreshToken, authService.cookieOptions())
    .status(OK)
    .json({ success: true, message: "Token refreshed", data: { accessToken: newAccessToken }, reqId: req.reqId });
});

const logout = asyncHandler(async (req, res) => {
  res.clearCookie("refreshToken", { path: "/api/v1/auth/refresh" });
  res.status(OK).json({ success: true, message: "Logged out", reqId: req.reqId });
});

const me = asyncHandler(async (req, res) => {
  res.json({ success: true, data: req.user, reqId: req.reqId });
});

const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.validated?.body || req.body;
  const result = await authService.forgotPassword({ email });
  res.status(OK).json({
    success: true,
    message: result.message,
    reqId: req.reqId,
  });
});

const resetPassword = asyncHandler(async (req, res) => {
  const { token, password } = req.validated?.body || req.body;
  const { message, user, accessToken, refreshToken } = await authService.resetPassword({
    token,
    password,
  });
  res
    .cookie("refreshToken", refreshToken, authService.cookieOptions())
    .status(OK)
    .json({
      success: true,
      message,
      data: { user, accessToken },
      reqId: req.reqId,
    });
});

const changePassword = asyncHandler(async (req, res) => {
  const { currentPassword, newPassword } = req.validated?.body || req.body;
  const { message, accessToken, refreshToken } = await authService.changePassword(
    req.user.id,
    { currentPassword, newPassword }
  );

  res
    .cookie("refreshToken", refreshToken, authService.cookieOptions())
    .status(OK)
    .json({
      success: true,
      message,
      data: { accessToken },
      reqId: req.reqId,
    });
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

module.exports = { register, login, refresh, logout, me ,forgotPassword,resetPassword,changePassword,adminCreateUser};
