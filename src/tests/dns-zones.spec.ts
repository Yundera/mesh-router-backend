import { describe, it, before, beforeEach, after } from "mocha";
import { expect } from "chai";
import { getRedisClient, closeRedisClient } from "../redis/redisClient.js";
import { Route } from "../services/Routes.js";
import {
  agentPublicIps,
  allowKey,
  allowZoneName,
  expandIPv6,
  noteRoutes,
  syncAllow,
} from "../services/DnsZones.js";
import * as pdns from "../services/PowerDns.js";

/**
 * The ip.<zone> allowlist. The pure helpers always run; the rest needs a PowerDNS
 * primary (mesh-router-nameserver deploy/primary) and is skipped without PDNS_API_URL:
 *   PDNS_API_URL=http://127.0.0.1:18081 PDNS_API_KEY=testkey REDIS_URL=redis://127.0.0.1:16379 \
 *     npx mocha dist/tests/dns-zones.spec.js
 */

process.env.SERVER_DOMAIN = process.env.SERVER_DOMAIN || "test.example.com";
process.env.DNS_IP_ZONE = process.env.DNS_IP_ZONE || "ip.test.example.com";

function agent(ip: string, extra: Partial<Route> = {}): Route {
  return { ip, port: 443, priority: 1, source: "agent", ...extra };
}

describe("DNS allowlist keys", () => {
  it("dashes IPv4 and expands IPv6 to 32 hex digits", () => {
    expect(allowKey("161.97.177.252")).to.equal("161-97-177-252");
    expect(expandIPv6("2001:DB8:3021::1")).to.equal("20010db8302100000000000000000001");
    expect(allowKey("::1")).to.equal("00000000000000000000000000000001");
    expect(allowKey("2a01:4f8:1:2:3:4:5:6")).to.equal("2a0104f8000100020003000400050006");
    expect(allowKey("::ffff:1.2.3.4")).to.equal(null);
    expect(allowKey("not-an-ip")).to.equal(null);
  });

  it("keeps public agent IPs only, deduplicated, both route types", () => {
    const ips = agentPublicIps([
      agent("80.241.218.30", { type: "domain", domain: "80-241-218-30.ip.test.example.com" }),
      agent("80.241.218.30", { port: 80, scheme: "http" }),
      agent("192.168.1.10"),
      agent("10.0.0.1"),
      { ip: "172.30.0.3", port: 80, priority: 2, source: "tunnel" },
      agent("2a01:4f8::1"),
    ]);
    expect(ips).to.deep.equal(["80.241.218.30", "2a01:4f8::1"]);
  });
});

describe("DNS allowlist on the PowerDNS primary", function () {
  this.timeout(20_000);
  const zone = () => allowZoneName();
  const v4 = "198.51.100.7";
  const v6 = "2a01:4f8::1";

  async function names(): Promise<string[]> {
    const z = await pdns.getZone(zone());
    return (z?.rrsets || [])
      .filter((r) => r.type === "A" || r.type === "AAAA")
      .map((r) => `${r.name} ${r.type} ${r.records.map((x) => x.content).join(",")}`)
      .sort();
  }

  before(function () {
    if (!process.env.PDNS_API_URL) this.skip();
  });

  beforeEach(async () => {
    await getRedisClient().del("dns:allow");
    if (await pdns.getZone(zone())) await pdns.deleteZone(zone());
  });

  after(async () => {
    if (process.env.PDNS_API_URL) await getRedisClient().del("dns:allow");
    await closeRedisClient();
  });

  it("creates the catalog and allow zone and writes a new agent IP at once", async () => {
    await noteRoutes([agent(v4), agent(v6), agent("10.1.2.3")]);
    expect(await names()).to.deep.equal([
      `198-51-100-7.${zone()}. A ${v4}`,
      `2a0104f8000000000000000000000001.${zone()}. AAAA ${v6}`,
    ]);
    const z = await pdns.getZone(zone());
    expect(z?.kind).to.equal("Master");
    expect(z?.catalog).to.equal(`catalog.${process.env.SERVER_DOMAIN}.invalid.`);
  });

  it("is idempotent: a second pass changes nothing and keeps the serial", async () => {
    await noteRoutes([agent(v4)]);
    const serial = (await pdns.getZone(zone()))?.serial;
    const r = await syncAllow();
    expect(r.added).to.deep.equal([]);
    expect(r.removed).to.deep.equal([]);
    expect((await pdns.getZone(zone()))?.serial).to.equal(serial);
    // a known IP's re-registration does not trigger a write either
    await noteRoutes([agent(v4)]);
    expect((await pdns.getZone(zone()))?.serial).to.equal(serial);
  });

  it("drops an IP unseen for longer than the grace period", async () => {
    await noteRoutes([agent(v4), agent("198.51.100.8")]);
    const old = Date.now() - 7 * 60 * 60 * 1000; // default grace 6 h
    await getRedisClient().zadd("dns:allow", old, v4);
    const r = await syncAllow();
    expect(r.pruned).to.deep.equal([v4]);
    expect(r.removed).to.deep.equal([v4]);
    expect(await names()).to.deep.equal([`198-51-100-8.${zone()}. A 198.51.100.8`]);
  });

  it("honours DNS_ALLOW_GRACE_SECONDS", async () => {
    process.env.DNS_ALLOW_GRACE_SECONDS = "60";
    try {
      await noteRoutes([agent(v4)]);
      await getRedisClient().zadd("dns:allow", Date.now() - 120_000, v4);
      expect((await syncAllow()).removed).to.deep.equal([v4]);
    } finally {
      delete process.env.DNS_ALLOW_GRACE_SECONDS;
    }
  });

  it("repairs drift and rebuilds a lost zone", async () => {
    await noteRoutes([agent(v4)]);
    await pdns.patchRRsets(zone(), [
      { name: `9-9-9-9.${zone()}.`, type: "A", ttl: 60, changetype: "REPLACE", records: [{ content: "9.9.9.9", disabled: false }] },
    ]);
    expect((await syncAllow()).removed).to.deep.equal(["9.9.9.9"]);
    await pdns.deleteZone(zone());
    const r = await syncAllow();
    expect(r.created).to.deep.equal([zone()]);
    expect(await names()).to.deep.equal([`198-51-100-7.${zone()}. A ${v4}`]);
  });

  it("dry run writes nothing", async () => {
    await getRedisClient().zadd("dns:allow", Date.now(), v4);
    const r = await syncAllow(true);
    expect(r.added).to.deep.equal([v4]);
    expect(await pdns.getZone(zone())).to.equal(null);
  });
});
