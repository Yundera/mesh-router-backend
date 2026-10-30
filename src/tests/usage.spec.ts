import { describe, it, before, after } from "mocha";
import { expect } from "chai";
import request from "supertest";
import type { Application } from "express";

import { createTestApp } from "./test-app.js";
import { getRedisClient } from "../redis/redisClient.js";
import { generateKeyPair } from "../library/KeyLib.js";
import { utcDateString, isReportableDate, isValidAppName } from "../services/Usage.js";
import {
  cleanupTestUsage,
  createTestUser,
  deleteTestUser,
  generateTestUserId,
  signMessage,
} from "./test-helpers.js";

const DAY_MS = 24 * 60 * 60 * 1000;
const TODAY = utcDateString();
const YESTERDAY = utcDateString(new Date(Date.now() - DAY_MS));

describe("Usage helpers", () => {
  it("accepts today and yesterday only", () => {
    const now = new Date("2026-10-30T00:05:00Z");
    expect(isReportableDate("2026-10-30", now)).to.equal(true);
    expect(isReportableDate("2026-10-29", now)).to.equal(true);
    expect(isReportableDate("2026-10-28", now)).to.equal(false);
    expect(isReportableDate("2026-10-31", now)).to.equal(false);
    expect(isReportableDate("garbage", now)).to.equal(false);
    expect(isReportableDate(undefined, now)).to.equal(false);
  });

  it("accepts host labels and the _root/_custom buckets", () => {
    for (const ok of ["nextcloud", "app-1", "_root", "_custom", "a"]) {
      expect(isValidAppName(ok), ok).to.equal(true);
    }
    for (const bad of ["", "Nextcloud", "a.b", "a_b", "-x", "x".repeat(64), 42, null]) {
      expect(isValidAppName(bad), String(bad)).to.equal(false);
    }
  });
});

describe("Usage report API (POST /usage/:userid/:sig)", function () {
  this.timeout(15000);

  let app: Application;
  let uid: string;
  let sig: string;
  // Unique app names so we never collide with real usage data.
  const suffix = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
  const APP = `testapp-${suffix}`;
  const APP2 = `testapp2-${suffix}`;

  before(async () => {
    app = createTestApp();
    uid = generateTestUserId();
    const keys = await createTestUser(uid);
    sig = await signMessage(keys.privateKey, uid);
  });

  after(async () => {
    for (const date of [TODAY, YESTERDAY]) {
      await cleanupTestUsage(APP, uid, date);
      await cleanupTestUsage(APP2, uid, date);
    }
    await deleteTestUser(uid);
  });

  it("records the day's apps and is idempotent", async () => {
    const redis = getRedisClient();

    const res = await request(app)
      .post(`/usage/${uid}/${sig}`)
      .send({ date: TODAY, apps: [APP] })
      .expect(200);
    expect(res.body).to.deep.equal({ recorded: 1 });

    expect(await redis.scard(`usage:dau:${APP}:${TODAY}`)).to.equal(1);
    expect(await redis.sismember(`usage:apps:${TODAY}`, APP)).to.equal(1);
    expect(await redis.sismember(`usage:active:${TODAY}`, uid)).to.equal(1);
    expect(await redis.sismember(`usage:user:${uid}:${TODAY}`, APP)).to.equal(1);

    // The agent re-sends the whole set when it grows: cardinality must not grow.
    await request(app)
      .post(`/usage/${uid}/${sig}`)
      .send({ date: TODAY, apps: [APP, APP2] })
      .expect(200);

    expect(await redis.scard(`usage:dau:${APP}:${TODAY}`)).to.equal(1);
    expect(await redis.scard(`usage:user:${uid}:${TODAY}`)).to.equal(2);

    // TTL is applied so the bucket rolls off.
    expect(await redis.ttl(`usage:dau:${APP}:${TODAY}`)).to.be.greaterThan(0);
  });

  it("files yesterday's set under yesterday", async () => {
    const redis = getRedisClient();
    await request(app)
      .post(`/usage/${uid}/${sig}`)
      .send({ date: YESTERDAY, apps: [APP] })
      .expect(200);
    expect(await redis.sismember(`usage:dau:${APP}:${YESTERDAY}`, uid)).to.equal(1);
  });

  it("refuses older or malformed dates with 400", async () => {
    const old = utcDateString(new Date(Date.now() - 2 * DAY_MS));
    await request(app).post(`/usage/${uid}/${sig}`).send({ date: old, apps: [APP] }).expect(400);
    await request(app).post(`/usage/${uid}/${sig}`).send({ apps: [APP] }).expect(400);
  });

  it("refuses a body without an apps array with 400", async () => {
    await request(app).post(`/usage/${uid}/${sig}`).send({ date: TODAY }).expect(400);
  });

  it("refuses an invalid signature with 401", async () => {
    const other = await signMessage((await generateKeyPair()).priv, uid);
    await request(app)
      .post(`/usage/${uid}/${other}`)
      .send({ date: TODAY, apps: [APP] })
      .expect(401);
  });

  it("answers 404 for an unknown user", async () => {
    await request(app)
      .post(`/usage/${generateTestUserId()}/${sig}`)
      .send({ date: TODAY, apps: [APP] })
      .expect(404);
  });

  it("drops malformed app names and ignores a uid in the body", async () => {
    const redis = getRedisClient();
    const res = await request(app)
      .post(`/usage/${uid}/${sig}`)
      .send({ date: TODAY, uid: "someone-else", apps: [APP, "Bad.Name", "", 42, APP] })
      .expect(200);
    expect(res.body).to.deep.equal({ recorded: 1 });
    expect(await redis.smembers(`usage:dau:${APP}:${TODAY}`)).to.deep.equal([uid]);
  });
});

