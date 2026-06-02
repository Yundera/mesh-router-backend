import { describe, it, before, after } from "mocha";
import { expect } from "chai";
import request from "supertest";
import cors from "cors";
import express from "express";
import type { Application } from "express";

// Usage ingest is Firebase-free (it only needs SERVICE_API_KEY + Redis), so we
// build a minimal app here rather than createTestApp() to avoid the Firebase init.
process.env.REDIS_URL = process.env.REDIS_URL || "redis://localhost:6379";
process.env.SERVICE_API_KEY = process.env.SERVICE_API_KEY || "test-service-key";

import { routerAPI } from "../services/RouterAPI.js";
import { getRedisClient } from "../redis/redisClient.js";
import { utcDateString } from "../services/Usage.js";
import { cleanupTestUsage } from "./test-helpers.js";

const SECRET = process.env.SERVICE_API_KEY as string;
const TODAY = utcDateString();

function buildApp(): Application {
  const app = express();
  app.use(express.json());
  app.use(cors());
  routerAPI(app);
  return app;
}

describe("Usage ingest API", () => {
  let app: Application;
  // Unique test identifiers so we never collide with real usage data.
  const suffix = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
  const APP = `testapp_${suffix}`;
  const UID = `testuser_${suffix}`;

  before(() => {
    app = buildApp();
  });

  after(async () => {
    await cleanupTestUsage(APP, UID, TODAY);
  });

  it("records an event and is idempotent", async () => {
    const redis = getRedisClient();

    await request(app)
      .post("/internal/usage/ingest")
      .set("Authorization", `Bearer ${SECRET}`)
      .send({ events: [{ uid: UID, app: APP }] })
      .expect(204);

    expect(await redis.scard(`usage:dau:${APP}:${TODAY}`)).to.equal(1);
    expect(await redis.sismember(`usage:apps:${TODAY}`, APP)).to.equal(1);
    expect(await redis.sismember(`usage:active:${TODAY}`, UID)).to.equal(1);
    expect(await redis.sismember(`usage:user:${UID}:${TODAY}`, APP)).to.equal(1);

    // Same tuple again — cardinality must not grow (idempotent SADD).
    await request(app)
      .post("/internal/usage/ingest")
      .set("Authorization", `Bearer ${SECRET}`)
      .send({ events: [{ uid: UID, app: APP }] })
      .expect(204);

    expect(await redis.scard(`usage:dau:${APP}:${TODAY}`)).to.equal(1);

    // TTL is applied so the bucket rolls off.
    expect(await redis.ttl(`usage:dau:${APP}:${TODAY}`)).to.be.greaterThan(0);
  });

  it("rejects a missing/invalid token with 401", async () => {
    await request(app)
      .post("/internal/usage/ingest")
      .send({ events: [{ uid: UID, app: APP }] })
      .expect(401);

    await request(app)
      .post("/internal/usage/ingest")
      .set("Authorization", "Bearer wrong-key")
      .send({ events: [{ uid: UID, app: APP }] })
      .expect(401);
  });

  it("rejects a body without an events array with 400", async () => {
    await request(app)
      .post("/internal/usage/ingest")
      .set("Authorization", `Bearer ${SECRET}`)
      .send({ nope: true })
      .expect(400);
  });

  it("ignores malformed entries but accepts the batch", async () => {
    const redis = getRedisClient();
    await request(app)
      .post("/internal/usage/ingest")
      .set("Authorization", `Bearer ${SECRET}`)
      .send({ events: [{ uid: UID, app: APP }, { uid: "", app: APP }, { app: APP }, "junk"] })
      .expect(204);

    // Only the one well-formed entry counts.
    expect(await redis.scard(`usage:dau:${APP}:${TODAY}`)).to.equal(1);
  });
});
