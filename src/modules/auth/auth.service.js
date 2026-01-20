const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const User = require("../../modules/auth/auth.model");
const AppError = require("../../utils/AppError");
const {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
} = require("../../utils/tokens");

const {
  UNAUTHORIZED,
  CONFLICT,
  BAD_REQUEST,
  NOT_FOUND,
} = require("../../constant/httpStatus");

const SALT_ROUNDS = 10;


 /* Cookie options for refresh token cookie.
 * Best practice: refresh token should be stored in HttpOnly cookie at controller layer.
 */
function cookieOptions() {
  const secure = String(process.env.COOKIE_SECURE) === "true";
  const sameSite = process.env.COOKIE_SAMESITE || "lax";

  return {
    httpOnly: true,
    secure,
    sameSite,
    path: "/api/v1/auth/refresh",
  };
}

function normalizeEmail(email) {
  if (!email) return "";
  return String(email).trim().toLowerCase();
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

async function register({ name, email, password }) {
  email = normalizeEmail(email);

  if (!name) throw new AppError("Name is required", BAD_REQUEST);
  if (!email) throw new AppError("Email is required", BAD_REQUEST);
  if (!password) throw new AppError("Password is required", BAD_REQUEST);

  const exists = await User.findOne({ email });
  if (exists) throw new AppError("Email already registered", CONFLICT);

  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

  const user = await User.create({ name, email, password: passwordHash });

  const accessToken = signAccessToken({ id: user._id, role: user.role });
  const refreshToken = signRefreshToken({ id: user._id });

  const refreshTokenHash = await bcrypt.hash(refreshToken, SALT_ROUNDS);
  await User.updateOne({ _id: user._id }, { refreshTokenHash });

  return {
    user: { id: user._id, name: user.name, email: user.email, role: user.role },
    accessToken,
    refreshToken, // controller may set cookie instead of returning this
  };
}

async function login({ email, password }) {
  email = normalizeEmail(email);

  if (!email) throw new AppError("Email is required", BAD_REQUEST);
  if (!password) throw new AppError("Password is required", BAD_REQUEST);

  const user = await User.findOne({ email }).select("+password +refreshTokenHash");
  if (!user) throw new AppError("Invalid email or password", UNAUTHORIZED);

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) throw new AppError("Invalid email or password", UNAUTHORIZED);
  const accessToken = signAccessToken({ id: user._id, role: user.role });
  const refreshToken = signRefreshToken({ id: user._id });

  const refreshTokenHash = await bcrypt.hash(refreshToken, SALT_ROUNDS);
  await User.updateOne({ _id: user._id }, { refreshTokenHash });

  return {
    user: { id: user._id, name: user.name, email: user.email, role: user.role },
    accessToken,
    refreshToken, // controller may set cookie instead of returning this
  };
}

async function refresh(refreshTokenFromCookie) {
  if (!refreshTokenFromCookie) {
    throw new AppError("Refresh token missing", UNAUTHORIZED);
  }

  let decoded;
  try {
    decoded = verifyRefreshToken(refreshTokenFromCookie);
  } catch {
    throw new AppError("Invalid/expired refresh token", UNAUTHORIZED);
  }

  const user = await User.findById(decoded.id).select("+refreshTokenHash");
  if (!user || !user.refreshTokenHash) throw new AppError("Unauthorized", UNAUTHORIZED);

  const match = await bcrypt.compare(refreshTokenFromCookie, user.refreshTokenHash);
  if (!match) throw new AppError("Refresh token revoked", UNAUTHORIZED);

  const newAccessToken = signAccessToken({ id: user._id, role: user.role });
  const newRefreshToken = signRefreshToken({ id: user._id });

  const newHash = await bcrypt.hash(newRefreshToken, SALT_ROUNDS);
  await User.updateOne({ _id: user._id }, { refreshTokenHash: newHash });

  return { newAccessToken, newRefreshToken };
}

async function logout(userId) {
  if (!userId) return;
  await User.updateOne({ _id: userId }, { $unset: { refreshTokenHash: 1 } });
}

/**
 * Dev-friendly forgotPassword: returns rawToken (so you can test in Postman).
 * Production best practice: email the rawToken link, don't return rawToken in response.
 */
async function forgotPassword({ email }) {
  email = normalizeEmail(email);
  if (!email) throw new AppError("Email is required", BAD_REQUEST);

  const user = await User.findOne({ email });
  const message = "If the email exists, a reset link has been sent.";
  if (!user) return { message };

  const rawToken = crypto.randomBytes(32).toString("hex");

  await User.updateOne(
    { _id: user._id },
    {
      resetPasswordTokenHash: hashToken(rawToken),
      resetPasswordExpiresAt: new Date(Date.now() + 15 * 60 * 1000),
    }
  );

  return { message, rawToken }; // return rawToken for now (dev/testing)
}

async function resetPassword({ token, password }) {
  if (!token) throw new AppError("Reset token is required", BAD_REQUEST);
  if (!password) throw new AppError("Password is required", BAD_REQUEST);

  const tokenHash = hashToken(token);

  const user = await User.findOne({
    resetPasswordTokenHash: tokenHash,
    resetPasswordExpiresAt: { $gt: new Date() },
  }).select("+password +refreshTokenHash");

  if (!user) throw new AppError("Reset token is invalid or expired", BAD_REQUEST);

  user.password = await bcrypt.hash(password, SALT_ROUNDS);
  user.resetPasswordTokenHash = undefined;
  user.resetPasswordExpiresAt = undefined;
  user.passwordChangedAt = new Date();

  // revoke old refresh token(s)
  user.refreshTokenHash = undefined;

  await user.save();

  const accessToken = signAccessToken({ id: user._id, role: user.role });
  const refreshToken = signRefreshToken({ id: user._id });
  const refreshTokenHash = await bcrypt.hash(refreshToken, SALT_ROUNDS);

  await User.updateOne({ _id: user._id }, { refreshTokenHash });

  return {
    message: "Password reset successful",
    user: { id: user._id, name: user.name, email: user.email, role: user.role },
    accessToken,
    refreshToken,
  };
}

async function changePassword(userId, { currentPassword, newPassword }) {
  if (!userId) throw new AppError("User id missing", UNAUTHORIZED);
  if (!currentPassword) throw new AppError("Current password is required", BAD_REQUEST);
  if (!newPassword) throw new AppError("New password is required", BAD_REQUEST);

  const user = await User.findById(userId).select("+password +refreshTokenHash");
  if (!user) throw new AppError("User not found", NOT_FOUND);

  const ok = await bcrypt.compare(currentPassword, user.password);
  if (!ok) throw new AppError("Current password is incorrect", UNAUTHORIZED);

  user.password = await bcrypt.hash(newPassword, SALT_ROUNDS);
  user.passwordChangedAt = new Date();

  // revoke refresh token(s) so old sessions die
  user.refreshTokenHash = undefined;
  await user.save();

  const accessToken = signAccessToken({ id: user._id, role: user.role });
  const refreshToken = signRefreshToken({ id: user._id });

  const refreshTokenHash = await bcrypt.hash(refreshToken, SALT_ROUNDS);
  await User.updateOne({ _id: user._id }, { refreshTokenHash });

  return {
    message: "Password changed successfully",
    accessToken,
    refreshToken,
  };
}

async function adminCreateUser({ name, email, password, role }) {
  email = normalizeEmail(email);

  if (!name) throw new AppError("Name is required", BAD_REQUEST);
  if (!email) throw new AppError("Email is required", BAD_REQUEST);
  if (!password) throw new AppError("Password is required", BAD_REQUEST);

  const exists = await User.findOne({ email });
  if (exists) throw new AppError("Email already registered", CONFLICT);

  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

  const user = await User.create({
    name,
    email,
    password: passwordHash,
    role: role || "user",
  });

  return {
    message: "User created by admin",
    user: { id: user._id, name: user.name, email: user.email, role: user.role },
  };
}

module.exports = {
  register,
  login,
  refresh,
  logout,
  cookieOptions,
  forgotPassword,
  resetPassword,
  changePassword,
  adminCreateUser,
};
