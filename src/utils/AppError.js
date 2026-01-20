const {INTERNAL_SERVER_ERROR}=require("../constant/httpStatus")

class AppError extends Error {
    constructor(message, statusCode = INTERNAL_SERVER_ERROR, isOperational = true) {
      super(message);
      this.statusCode = statusCode;
      this.isOperational = isOperational;
    }
  }
  
  module.exports = AppError;
  