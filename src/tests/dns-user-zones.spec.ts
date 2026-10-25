import { describe, it, before, beforeEach, after } from "mocha";
import { expect } from "chai";
import https from "https";
import { AddressInfo } from "net";
import forge from "node-forge";
import { getRedisClient, closeRedisClient } from "../redis/redisClient.js";
import { registerRoutes, deleteRoutes } from "../services/Routes.js";
import { answer, catchUpSerial, desiredUserRRsets, dropUserZone, syncUser, userZoneName, ScopeUser } from "../services/DnsZones.js";
import { DnsProbeState, probeBox, saveProbeState } from "../services/DnsProbe.js";
import * as pdns from "../services/PowerDns.js";

/**
 * Per-user zones (mesh-router-nameserver architecture §4.2, §10.2). The answer rule and
 * the probe always run; the zone tests need a PowerDNS primary and Redis and are
 * skipped without PDNS_API_URL (see dns-zones.spec.ts for the command).
 */

process.env.SERVER_DOMAIN = process.env.SERVER_DOMAIN || "test.example.com";
process.env.DNS_GATEWAY_IPS = "192.0.2.10,192.0.2.11";
process.env.DNS_NS_HOSTS = "ns1.test.example.com,ns2.test.example.com";

const GW = ["192.0.2.10", "192.0.2.11"];
const BOX = "198.51.100.20";

function probe(cert: DnsProbeState["cert"], publicIp = BOX): DnsProbeState {
  return { publicIp, cert, probeOk: true, reason: `cert ${cert}`, at: new Date().toISOString() };
}

describe("DNS answer rule", () => {
  const base = { publicIp: BOX, probe: probe("trusted"), gatewayIps: GW };

  it("answers the box only with a trusted, fresh probe of the same IP", () => {
    expect(answer(base)).to.include({ kind: "direct" });
    expect(answer(base).ips).to.deep.equal([BOX]);
    expect(answer({ ...base, probe: probe("mesh-ca") })).to.include({ kind: "gateway", reason: "cert mesh-ca" });
    expect(answer({ ...base, probe: probe("none") }).kind).to.equal("gateway");
    expect(answer({ ...base, probe: null })).to.include({ kind: "gateway", reason: "not probed yet" });
    expect(answer({ ...base, probe: probe("trusted", "198.51.100.99") }).kind).to.equal("gateway");
    expect(answer({ ...base, publicIp: null }).ips).to.deep.equal(GW);
  });

  it("honours force", () => {
    expect(answer({ ...base, force: "gateway" })).to.include({ kind: "gateway", reason: "forced to the gateway" });
    expect(answer({ ...base, probe: null, force: "direct" })).to.include({ kind: "direct", reason: "forced direct (admin)" });
    expect(answer({ ...base, publicIp: null, force: "direct" }).kind).to.equal("gateway");
  });

  it("lists a host only when its answer differs from the user's", () => {
    const a = answer({ ...base, hostForce: { Immich: "gateway", photos: "direct" } });
    expect(Object.keys(a.hosts)).to.deep.equal(["immich"]);
    expect(a.hosts.immich.ips).to.deep.equal(GW);
    const b = answer({ ...base, probe: null, hostForce: { immich: "direct" } });
    expect(b.hosts.immich).to.include({ kind: "direct" });
  });

  it("builds apex, wildcard, host and NS RRsets", () => {
    const rr = desiredUserRRsets("wisera.test.example.com", answer({ ...base, hostForce: { immich: "gateway" } }), ["ns2.x", "ns1.x"]);
    expect(rr.map((r) => `${r.name} ${r.type} ${r.records.map((x) => x.content).join(",")}`)).to.deep.equal([
      "wisera.test.example.com. NS ns1.x.,ns2.x.",
      `wisera.test.example.com. A ${BOX}`,
      `*.wisera.test.example.com. A ${BOX}`,
      `immich.wisera.test.example.com. A ${GW.join(",")}`,
    ]);
  });
});

/** A CA and a leaf for `names`, valid `days` from now (negative = expired). */
function makeCerts(names: string[], days: number) {
  const pki = forge.pki;
  const caKeys = pki.rsa.generateKeyPair(2048);
  const ca = pki.createCertificate();
  ca.publicKey = caKeys.publicKey;
  ca.serialNumber = "01";
  ca.validity.notBefore = new Date(Date.now() - 86_400_000 * 30);
  ca.validity.notAfter = new Date(Date.now() + 86_400_000 * 365);
  ca.setSubject([{ name: "commonName", value: "probe test CA" }]);
  ca.setIssuer(ca.subject.attributes);
  ca.setExtensions([{ name: "basicConstraints", cA: true }, { name: "keyUsage", keyCertSign: true, cRLSign: true }]);
  ca.sign(caKeys.privateKey, forge.md.sha256.create());

  const keys = pki.rsa.generateKeyPair(2048);
  const leaf = pki.createCertificate();
  leaf.publicKey = keys.publicKey;
  leaf.serialNumber = "02";
  leaf.validity.notBefore = new Date(Date.now() - 86_400_000 * 10);
  leaf.validity.notAfter = new Date(Date.now() + 86_400_000 * days);
  leaf.setSubject([{ name: "commonName", value: names[0] }]);
  leaf.setIssuer(ca.subject.attributes);
  leaf.setExtensions([{ name: "subjectAltName", altNames: names.map((value) => ({ type: 2, value })) }]);
  leaf.sign(caKeys.privateKey, forge.md.sha256.create());
  return { ca: pki.certificateToPem(ca), cert: pki.certificateToPem(leaf), key: pki.privateKeyToPem(keys.privateKey) };
}

async function serve(cert: string, key: string): Promise<{ port: number; close: () => void }> {
  const server = https.createServer({ cert, key }, (_req, res) => res.end("ok"));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { port: (server.address() as AddressInfo).port, close: () => server.close() };
}

describe("DNS probe", function () {
  this.timeout(30_000);
  const zone = "wisera.test.example.com";
  let good: ReturnType<typeof makeCerts>;

  before(() => {
    good = makeCerts([zone, `*.${zone}`], 60);
  });

  it("trusted: both names verified by a trusted CA, outside the margin", async () => {
    const s = await serve(good.cert, good.key);
    try {
      const st = await probeBox(zone, "127.0.0.1", { port: s.port, trustedCa: [good.ca], meshCa: [] });
      expect(st).to.include({ cert: "trusted", probeOk: true, publicIp: "127.0.0.1" });
    } finally {
      s.close();
    }
  });

  it("mesh-ca: verified only by the mesh CA", async () => {
    const s = await serve(good.cert, good.key);
    try {
      const st = await probeBox(zone, "127.0.0.1", { port: s.port, trustedCa: [], meshCa: [good.ca] });
      expect(st.cert).to.equal("mesh-ca");
    } finally {
      s.close();
    }
  });

  it("not trusted: no wildcard, expiring soon, unreachable, no IP", async () => {
    const apexOnly = makeCerts([zone], 60);
    let s = await serve(apexOnly.cert, apexOnly.key);
    try {
      const st = await probeBox(zone, "127.0.0.1", { port: s.port, trustedCa: [apexOnly.ca], meshCa: [] });
      expect(st.cert).to.equal("none");
      expect(st.reason).to.contain(`mesh-probe.${zone}`);
    } finally {
      s.close();
    }
    const soon = makeCerts([zone, `*.${zone}`], 3);
    s = await serve(soon.cert, soon.key);
    try {
      const st = await probeBox(zone, "127.0.0.1", { port: s.port, trustedCa: [soon.ca], meshCa: [] });
      expect(st.cert).to.equal("none");
      expect(st.reason).to.contain("margin");
    } finally {
      s.close();
    }
    const down = await probeBox(zone, "127.0.0.1", { port: 1, trustedCa: [good.ca] });
    expect(down).to.include({ cert: "none", probeOk: false });
    expect((await probeBox(zone, null)).reason).to.contain("no public IP");
  });
});

describe("DNS user zones on the PowerDNS primary", function () {
  this.timeout(20_000);
  const uid = "testuserdnszone";
  const user: ScopeUser = { uid, label: "dnszonetest" };
  const zone = () => userZoneName(user.label);

  async function records(): Promise<string[]> {
    const z = await pdns.getZone(zone());
    return (z?.rrsets || [])
      .filter((r) => r.type === "A" || r.type === "NS")
      .map((r) => `${r.name} ${r.type} ${r.records.map((x) => x.content).sort().join(",")}`)
      .sort();
  }

  before(function () {
    if (!process.env.PDNS_API_URL) this.skip();
  });

  beforeEach(async () => {
    await getRedisClient().del(`dns:state:${uid}`);
    await deleteRoutes(uid);
    await dropUserZone(user.label);
  });

  after(async () => {
    if (process.env.PDNS_API_URL) {
      await dropUserZone(user.label);
      await deleteRoutes(uid);
      await getRedisClient().del(`dns:state:${uid}`);
    }
    await closeRedisClient();
  });

  it("creates the zone answering the gateway for an offline user", async () => {
    const r = await syncUser(user);
    expect(r.created).to.equal(true);
    expect(await records()).to.deep.equal([
      `*.${zone()}. A ${GW.join(",")}`,
      `${zone()}. A ${GW.join(",")}`,
      `${zone()}. NS ns1.test.example.com.,ns2.test.example.com.`,
    ]);
    const z = await pdns.getZone(zone());
    expect(z?.catalog).to.equal(`catalog.${process.env.SERVER_DOMAIN}.invalid.`);
    expect((await pdns.getZone(`catalog.${process.env.SERVER_DOMAIN}.invalid`))?.kind).to.equal("Producer");
  });

  it("is idempotent, flips to the box on a trusted probe, and back", async () => {
    await registerRoutes(uid, [{ ip: BOX, port: 443, priority: 1, source: "agent" }]);
    await syncUser(user);
    const serial = (await pdns.getZone(zone()))?.serial;
    expect((await syncUser(user)).changed).to.deep.equal([]);
    expect((await pdns.getZone(zone()))?.serial).to.equal(serial);

    await saveProbeState(uid, probe("trusted"));
    const flipped = await syncUser(user);
    expect(flipped.answer.kind).to.equal("direct");
    expect(await records()).to.include(`${zone()}. A ${BOX}`);
    expect(await records()).to.include(`*.${zone()}. A ${BOX}`);

    await saveProbeState(uid, probe("mesh-ca"));
    expect((await syncUser(user)).answer.kind).to.equal("gateway");
    expect(await records()).to.include(`${zone()}. A ${GW.join(",")}`);
  });

  it("writes a host record for a per-host force and removes it again", async () => {
    await registerRoutes(uid, [{ ip: BOX, port: 443, priority: 1, source: "agent" }]);
    await saveProbeState(uid, probe("trusted"));
    await syncUser({ ...user, dns: { hostForce: { immich: "gateway" } } });
    expect(await records()).to.include(`immich.${zone()}. A ${GW.join(",")}`);
    await syncUser(user);
    expect((await records()).some((r) => r.startsWith("immich."))).to.equal(false);
  });

  it("removing a zone bumps the catalog serial so the secondaries drop it", async () => {
    await syncUser(user);
    const catalog = `catalog.${process.env.SERVER_DOMAIN}.invalid`;
    const before = (await pdns.getZone(catalog))?.serial ?? 0;
    expect(await dropUserZone(user.label)).to.equal(true);
    expect((await pdns.getZone(catalog))?.serial).to.be.greaterThan(before);
    expect(await pdns.getZone(zone())).to.equal(null);
  });

  it("lifts a zone's serial above a nameserver that is ahead (recreated primary)", async function () {
    // PDNS_AHEAD_API / PDNS_AHEAD_DNS: a second PowerDNS standing in for a secondary
    // that still holds the zone at a higher serial
    const api = process.env.PDNS_AHEAD_API;
    const dnsAddr = process.env.PDNS_AHEAD_DNS;
    if (!api || !dnsAddr) this.skip();
    const name = pdns.fqdn(zone());
    const h = { "X-API-Key": "testkey", "Content-Type": "application/json" };
    const base = `${api}/api/v1/servers/localhost/zones`;
    await fetch(`${base}/${name}`, { method: "DELETE", headers: h });
    await fetch(base, { method: "POST", headers: h, body: JSON.stringify({ name, kind: "Primary", nameservers: ["ns1.example."] }) });
    const soa = (await (await fetch(`${base}/${name}`, { headers: h })).json()).rrsets.find((r: any) => r.type === "SOA");
    const ahead = soa.records[0].content.split(" ");
    ahead[2] = "2099010150";
    await fetch(`${base}/${name}`, { method: "PATCH", headers: h, body: JSON.stringify({ rrsets: [{ ...soa, changetype: "REPLACE", records: [{ content: ahead.join(" "), disabled: false }] }] }) });
    try {
      await syncUser(user);
      expect(await catchUpSerial(zone(), [dnsAddr])).to.equal(true);
      expect((await pdns.getZone(zone()))?.serial).to.be.greaterThan(2099010150);
      expect(await catchUpSerial(zone(), [dnsAddr])).to.equal(false);
      // in sync (same serial on the nameserver): nothing to lift
      const ours = (await pdns.getZone(zone()))!.serial;
      // PowerDNS adds one to a patched serial: ours - 1 lands on ours
      ahead[2] = String(ours - 1);
      await fetch(`${base}/${name}`, { method: "PATCH", headers: h, body: JSON.stringify({ rrsets: [{ ...soa, changetype: "REPLACE", records: [{ content: ahead.join(" "), disabled: false }] }] }) });
      const mirrored = (await (await fetch(`${base}/${name}`, { headers: h })).json()).serial;
      expect(mirrored).to.be.at.most(ours);
      expect(await catchUpSerial(zone(), [dnsAddr])).to.equal(false);
      expect((await pdns.getZone(zone()))?.serial).to.equal(ours);
    } finally {
      await fetch(`${base}/${name}`, { method: "DELETE", headers: h });
    }
  });

  it("dry run writes nothing", async () => {
    const r = await syncUser(user, true);
    expect(r.changed.length).to.be.greaterThan(0);
    expect(await pdns.getZone(zone())).to.equal(null);
  });
});
