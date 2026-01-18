const request = require("supertest");
const app = require("../src/app");

describe("Base API tests", () => {
  it("GET / should work", async () => {
    const res = await request(app).get("/");
    expect(res.statusCode).toBe(200);
  });

  it("GET /api/v1/demo/ok should return success", async () => {
    const res = await request(app).get("/api/v1/demo/ok");
    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);
  });

  it("GET /api/v1/demo/sync-error should return 400", async () => {
    const res = await request(app).get("/api/v1/demo/sync-error");
    expect(res.statusCode).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toContain("SYNC");
  });
});
