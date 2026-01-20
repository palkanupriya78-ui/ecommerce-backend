const AppError = require("../utils/AppError");
const {UNPROCESSABLE_ENTITY}=require("../constant/httpStatus")
module.exports = function validate(schema) {
  return (req, res, next) => {
    try {
      const result = schema.safeParse({
        body: req.body,
        params: req.params,
        query: req.query,
      });

      if (!result.success) {
        const message = result.error.issues
          .map((i) => `${i.path.join(".")}: ${i.message}`)
          .join(", ");

        return next(new AppError(message, UNPROCESSABLE_ENTITY));
      }
      req.validated = result.data;
      next();
    } catch (err) {
      next(err);
    }
  };
};
