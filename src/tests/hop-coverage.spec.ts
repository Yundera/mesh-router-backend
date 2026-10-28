import { describe, it } from "mocha";
import { expect } from "chai";
import { acceptsProxyProtocol, setProxyProtocol, PROXY_PROTOCOL_TTL_SECONDS } from "../services/HopNames.js";
import { getRedisClient, closeRedisClient } from "../redis/redisClient.js";

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
