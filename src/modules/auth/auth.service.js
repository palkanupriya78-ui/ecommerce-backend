const bcrypt = require("bcryptjs");
const User = require("../../modules/auth/auth.model");
const AppError = require("../../utils/AppError");
const {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
} = require("../../utils/tokens");
const {UNAUTHORIZED,CONFLICT}=require("../../constant/httpStatus")
const SALT = 10;

function cookieOptions() {
  const secure = String(process.env.COOKIE_SECURE) === "true";
  const sameSite = process.env.COOKIE_SAMESITE || "lax"; // lax in dev
  return {
    httpOnly: true,
    secure,
    sameSite,
    path: "/api/v1/auth/refresh",
    // you can also set domain in prod
  };
}

async function register({ name, email, password }) {
  const exists = await User.findOne({ email });
  if (exists) throw new AppError("Email already registered", CONFLICT);

  const passwordHash = await bcrypt.hash(password, SALT);

  const user = await User.create({ name, email, password: passwordHash });

  const accessToken = signAccessToken({ id: user._id, role: user.role });
  const refreshToken = signRefreshToken({ id: user._id });

  const refreshTokenHash = await bcrypt.hash(refreshToken, SALT);
  await User.updateOne({ _id: user._id }, { refreshTokenHash });

  return {
    user: { id: user._id, name: user.name, email: user.email, role: user.role },
    accessToken,
    refreshToken,
  };
}

async function login({ email, password }) {
  const user = await User.findOne({ email }).select("+password +refreshTokenHash");
  if (!user) throw new AppError("Invalid email or password", UNAUTHORIZED);

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) throw new AppError("Invalid email or password", UNAUTHORIZED);

  const accessToken = signAccessToken({ id: user._id, role: user.role });
  const refreshToken = signRefreshToken({ id: user._id });

  const refreshTokenHash = await bcrypt.hash(refreshToken, SALT);
  await User.updateOne({ _id: user._id }, { refreshTokenHash });

  return {
    user: { id: user._id, name: user.name, email: user.email, role: user.role },
    accessToken,
    refreshToken,
  };
}

async function refresh(refreshTokenFromCookie) {
  if (!refreshTokenFromCookie) throw new AppError("Refresh token missing", UNAUTHORIZED);

  let decoded;
  try {
    decoded = verifyRefreshToken(refreshTokenFromCookie);
  } catch {
    throw new AppError("Invalid/expired refresh token", UNAUTHORIZED);
  }

  const user = await User.findById(decoded.id).select("+refreshTokenHash");
  if (!user || !user.refreshTokenHash) throw new AppError("Unauthorized", UNAUTHORIZED);

  // token rotation check
  const match = await bcrypt.compare(refreshTokenFromCookie, user.refreshTokenHash);
  if (!match) throw new AppError("Refresh token revoked", UNAUTHORIZED);

  // rotate
  const newAccessToken = signAccessToken({ id: user._id, role: user.role });
  const newRefreshToken = signRefreshToken({ id: user._id });

  const newHash = await bcrypt.hash(newRefreshToken, SALT);
  await User.updateOne({ _id: user._id }, { refreshTokenHash: newHash });

  return { newAccessToken, newRefreshToken };
}

async function logout(userId) {
  if (!userId) return;
  await User.updateOne({ _id: userId }, { $unset: { refreshTokenHash: 1 } });
}

module.exports = { register, login, refresh, logout, cookieOptions };
