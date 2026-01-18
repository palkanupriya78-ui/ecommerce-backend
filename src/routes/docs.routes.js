const express = require("express");
const swaggerUi = require("swagger-ui-express");
const swaggerJSDoc = require("swagger-jsdoc");

const router = express.Router();

const swaggerSpec = swaggerJSDoc({
  definition: {
    openapi: "3.0.0",
    info: { title: "Kanu Node API", version: "1.0.0" },
    servers: [{ url: "/api/v1" }],
  },
  apis: ["./src/routes/*.js"],
});

router.use("/", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

module.exports = router;
