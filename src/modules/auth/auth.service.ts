const cryptoo = require("crypto");
const bcrypt = require("bcryptjs");
const User = require("../../modules/auth/auth.model");
const AppError = require("../../utils/AppError");
const { sendEmail } = require("../../utils/email");
const {generateOtp,generateResetToken}=require("../../utils/crypto");
const {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
} = require("../../utils/tokens");
const FileModel = require("../auth/file.model")
const {
  UNAUTHORIZED,
  CONFLICT,
  BAD_REQUEST,
  NOT_FOUND,
} = require("../../constant/httpStatus");
const {OTP_MAX_ATTEMPTS,RESET_SESSION_MINUTES,OTP_EXP_MINUTES}=require("../../constant/authConstant")

const SALT_ROUNDS = 10;
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

function normalizeEmail(email?: string) {
  if (!email) return "";
  return String(email).trim().toLowerCase();
}

function hashToken(token:string) {
  return cryptoo.createHash("sha256").update(token).digest("hex");
}

async function register({ name, email, password ,profilePhotoFile = null}) {
  email = normalizeEmail(email);

  if (!name) throw new AppError("Name is required", BAD_REQUEST);
  if (!email) throw new AppError("Email is required", BAD_REQUEST);
  if (!password) throw new AppError("Password is required", BAD_REQUEST);

  const exists = await User.findOne({ email });
  if (exists) throw new AppError("Email already registered", CONFLICT);

  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

  const user = await User.create({ name, email, password: passwordHash });
  if (profilePhotoFile) {
    const fileDoc = await FileModel.create({
      originalName: profilePhotoFile.originalname,
      fileName: profilePhotoFile.filename,
      mimeType: profilePhotoFile.mimetype,
      size: profilePhotoFile.size,
      path: `uploads/profile/${profilePhotoFile.filename}`, // same as multer destination
      entityType: "USER_PROFILE",
      entityId: String(user._id),
      uploadedBy: user._id,
    });

    await User.updateOne({ _id: user._id }, { profilePhoto: fileDoc._id });
  }
  const accessToken = signAccessToken({ id: user._id, role: user.role });
  const refreshToken = signRefreshToken({ id: user._id });

  const refreshTokenHash = await bcrypt.hash(refreshToken, SALT_ROUNDS);
  await User.updateOne({ _id: user._id }, { refreshTokenHash });
  const safeUser = await User.findById(user._id)
  .select("_id name email role profilePhoto")
  .populate("profilePhoto");
  return {
    user: {
      id: safeUser._id,
      name: safeUser.name,
      email: safeUser.email,
      role: safeUser.role,
      profilePhoto: safeUser.profilePhoto
        ? {
            id: safeUser.profilePhoto._id,
            path: safeUser.profilePhoto.path,
            mimeType: safeUser.profilePhoto.mimeType,
            originalName: safeUser.profilePhoto.originalName,
          }
        : null,
    },
    accessToken,
    refreshToken,
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
 *  OTP FLOW - Step 1: Request OTP
 */
async function forgotPasswordRequestOtp({ email }) {
  email = normalizeEmail(email);
  if (!email) throw new AppError("Email is required", BAD_REQUEST);

  // Always same message
  const message = "If the email exists, an OTP has been sent.";

  const user = await User.findOne({ email });
  if (!user) return { message };

  const otp = generateOtp();
  const otpHash = hashToken(otp);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

  // store in user embedded object (needs schema fields)
  await User.updateOne(
    { _id: user._id },
    {
      passwordResetOtp: {
        otpHash,
        expiresAt,
        attempts: 0,
        verifiedAt: null,
        usedAt: null,
      },
      passwordResetSession: null, // invalidate any old session
    }
  );

  await sendEmail({
    to: user.email,
    subject: "Your OTP for Password Reset",
    text: `Your OTP is ${otp}. It will expire in ${OTP_EXP_MINUTES} minutes.`,
    html: `<p>Your OTP is <b>${otp}</b>. It will expire in ${OTP_EXP_MINUTES} minutes.</p>`,
  });

  return { message };
}

/**
OTP FLOW - Step 2: Verify OTP -> returns resetToken
 */
async function forgotPasswordVerifyOtp({ email, otp }) {
  email = normalizeEmail(email);
  otp = String(otp || "").trim();

  if (!email) throw new AppError("Email is required", BAD_REQUEST);
  if (!otp) throw new AppError("OTP is required", BAD_REQUEST);

  const user = await User.findOne({ email }).select("+passwordResetOtp.otpHash");
  if (!user || !user.passwordResetOtp) throw new AppError("OTP expired or invalid", BAD_REQUEST);

  const pr = user.passwordResetOtp;

  if (pr.usedAt) throw new AppError("OTP already used", BAD_REQUEST);
  if (!pr.expiresAt || pr.expiresAt <= new Date()) throw new AppError("OTP expired or invalid", BAD_REQUEST);

  if ((pr.attempts || 0) >= OTP_MAX_ATTEMPTS) {
    // mark used to block further attempts
    await User.updateOne(
      { _id: user._id },
      { "passwordResetOtp.usedAt": new Date() }
    );
    throw new AppError("Too many attempts. Please request a new OTP.", 429);
  }

  const isMatch = hashToken(otp) === pr.otpHash;

  if (!isMatch) {
    await User.updateOne(
      { _id: user._id },
      { $inc: { "passwordResetOtp.attempts": 1 } }
    );
    throw new AppError("Invalid OTP", BAD_REQUEST);
  }

  const rawResetToken = generateResetToken();
  const tokenHash = hashToken(rawResetToken);
  const sessionExpiresAt = new Date(Date.now() + RESET_SESSION_MINUTES * 60 * 1000);

  await User.updateOne(
    { _id: user._id },
    {
      "passwordResetOtp.verifiedAt": new Date(),
      passwordResetSession: {
        tokenHash,
        expiresAt: sessionExpiresAt,
        usedAt: null,
      },
    }
  );

  return {
    message: "OTP verified",
    resetToken: rawResetToken,
    expiresInMinutes: RESET_SESSION_MINUTES,
  };
}

/**
 *OTP FLOW - Step 3: Reset password using resetToken
 */
async function forgotPasswordReset({ resetToken, newPassword, confirmPassword }) {
  if (!resetToken) throw new AppError("Reset token is required", UNAUTHORIZED);

  if (!newPassword) throw new AppError("New password is required", BAD_REQUEST);
  if (!confirmPassword) throw new AppError("Confirm password is required", BAD_REQUEST);
  if (newPassword !== confirmPassword) throw new AppError("Passwords do not match", BAD_REQUEST);
  if (String(newPassword).length < 6) throw new AppError("Password must be at least 6 characters", BAD_REQUEST);

  const tokenHash = hashToken(resetToken);

  const user = await User.findOne({
    "passwordResetSession.tokenHash": tokenHash,
    "passwordResetSession.usedAt": null,
    "passwordResetSession.expiresAt": { $gt: new Date() },
  }).select("+refreshTokenHash");

  if (!user) throw new AppError("Invalid or expired reset token", UNAUTHORIZED);

  const passwordHash = await bcrypt.hash(newPassword, SALT_ROUNDS);

  // update password + invalidate session + otp + refresh token
  await User.updateOne(
    { _id: user._id },
    {
      password: passwordHash,
      passwordChangedAt: new Date(),
      "passwordResetSession.usedAt": new Date(),
      "passwordResetOtp.usedAt": new Date(),
      $unset: { refreshTokenHash: 1 },
    }
  );

  return { message: "Password reset successful" };
}

/**
 *Existing reset-link flow (keep if you still want)
 * NOTE: removed TypeScript export syntax.
 */
async function forgotPassword({ email }) {
  email = normalizeEmail(email);
  if (!email) throw new AppError("Email is required", BAD_REQUEST);

  const user = await User.findOne({ email });

  const message = "If the email exists, a reset link has been sent.";
  if (!user) return { message };

  const rawToken = cryptoo.randomBytes(32).toString("hex");

  await User.updateOne(
    { _id: user._id },
    {
      resetPasswordTokenHash: hashToken(rawToken),
      resetPasswordExpiresAt: new Date(Date.now() + 15 * 60 * 1000),
    }
  );
  return { message };
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
  forgotPasswordRequestOtp,
  forgotPasswordVerifyOtp,
  forgotPasswordReset
};


