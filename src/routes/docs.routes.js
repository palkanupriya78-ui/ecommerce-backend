const express = require("express");
const swaggerUi = require("swagger-ui-express");
const swaggerJSDoc = require("swagger-jsdoc");
const {API_V1}=require("../constant/appConfig")
const router = express.Router();

const swaggerSpec = swaggerJSDoc({
  definition: {
    openapi: "3.0.0",
    info: { title: "Ecommerce Application Node API", version: "1.0.0" },
    servers: [{ url: API_V1 }],
  },
  apis: ["./src/routes/*.js","./src/modules/**/*.js"],
});

router.use("/", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

module.exports = router;
