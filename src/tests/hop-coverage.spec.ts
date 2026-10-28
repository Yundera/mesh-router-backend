import { describe, it } from "mocha";
import { expect } from "chai";
import { hopCoverage, acceptsProxyProtocol, setProxyProtocol, PROXY_PROTOCOL_TTL_SECONDS } from "../services/HopNames.js";
import { getRedisClient, closeRedisClient } from "../redis/redisClient.js";

describe("hop name coverage (gateway 1.6 readiness)", () => {
  it("lists the boxes with routes that hold no hop certificate", () => {
    const cov = hopCoverage(
      ["routes:sources", "routes:a@x.com:agent", "routes:a@x.com:tunnel", "routes:b@x.com:tunnel", "routes:c@x.com:agent"],
      new Set(["a@x.com", "c@x.com", "gone@x.com"])
    );
    expect(cov.boxes).to.deep.equal([
      { uid: "a@x.com", sources: ["agent", "tunnel"] },
      { uid: "b@x.com", sources: ["tunnel"] },
      { uid: "c@x.com", sources: ["agent"] },
    ]);
    expect(cov.missing).to.deep.equal([{ uid: "b@x.com", sources: ["tunnel"] }]);
  });

  it("is ready when every box holds one", () => {
    expect(hopCoverage(["routes:a@x.com:agent"], new Set(["a@x.com"])).missing).to.deep.equal([]);
    expect(hopCoverage([], new Set()).boxes).to.deep.equal([]);
  });
});

describe("PROXY protocol on the hop (box report)", function () {
  const uid = `proxy-test-${Date.now()}@x.com`;

  before(function () {
    if (!process.env.REDIS_URL) this.skip();
  });

  after(async () => {
    if (!process.env.REDIS_URL) return;
    await getRedisClient().del(`hop:proxy:${uid}`);
    await closeRedisClient();
  });

  it("is off until the box reports it, expires, and a false report clears it", async () => {
    expect(await acceptsProxyProtocol(uid)).to.equal(false);
    await setProxyProtocol(uid, true);
    expect(await acceptsProxyProtocol(uid)).to.equal(true);
    const ttl = await getRedisClient().ttl(`hop:proxy:${uid}`);
    expect(ttl).to.be.within(PROXY_PROTOCOL_TTL_SECONDS - 5, PROXY_PROTOCOL_TTL_SECONDS);
    await setProxyProtocol(uid, false);
    expect(await acceptsProxyProtocol(uid)).to.equal(false);
  });
});
