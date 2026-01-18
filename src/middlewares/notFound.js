const AppError = require("../utils/AppError");
const {NOT_FOUND}=require("../constant/httpStatus")
module.exports = (req, res, next) => {
  next(new AppError("Route not found", NOT_FOUND));
};
