const AppError = require("../utils/AppError");
const asyncHandler = require("../utils/asyncHandler");
const { verifyAccessToken } = require("../utils/tokens");
const User = require("../modules/auth/auth.model");
const {UNAUTHORIZED,FORBIDDEN}=require("../constant/httpStatus")

const protect = asyncHandler(async (req, res, next) => {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer")) {
    throw new AppError("Unauthorized: access token missing", UNAUTHORIZED);
  }

  const token = header.split(" ")[1];

  let decoded;
  try {
    decoded = verifyAccessToken(token);
  } catch {
    throw new AppError("Unauthorized: invalid/expired access token", UNAUTHORIZED);
  }

  const user = await User.findById(decoded.id);
  if (!user) throw new AppError("Unauthorized: user not found", UNAUTHORIZED);

  req.user = { id: user._id, role: user.role, email: user.email, name: user.name };
  next();
});

const restrictTo = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) return next(new AppError("Forbidden", FORBIDDEN));
  next();
};

module.exports = { protect, restrictTo };
