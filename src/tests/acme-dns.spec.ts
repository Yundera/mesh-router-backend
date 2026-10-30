import { describe, it, before, beforeEach, after } from "mocha";
import { expect } from "chai";
import request from "supertest";
import type { Application } from "express";
import { getFirestore, FieldValue } from "firebase-admin/firestore";
import { createTestApp } from "./test-app.js";
import { createTestUser, deleteTestUser, generateTestUserId, signMessage } from "./test-helpers.js";
import { NSL_ROUTER_COLLECTION } from "../DataBaseDTO/DataBaseNSLRouter.js";
import { getRedisClient, closeRedisClient } from "../redis/redisClient.js";
import { acmeLabelFromFqdn, addAcmeTxt, getAcmeTxt, isAcmeTxtValue } from "../services/AcmeDns.js";
import { dropUserZone, userZoneName } from "../services/DnsZones.js";
import * as pdns from "../services/PowerDns.js";

/**
 * DNS-01 challenges (acme-dns API + lego httpreq) and the owner's force toggle.
 * The pure checks always run; the rest needs Firestore (config/serviceAccount.json),
 * Redis and a PowerDNS primary, and is skipped without PDNS_API_URL (command in
 * dns-zones.spec.ts).
 */

process.env.SERVER_DOMAIN = process.env.SERVER_DOMAIN || "test.example.com";
process.env.DNS_GATEWAY_IPS = "192.0.2.10,192.0.2.11";
process.env.DNS_NS_HOSTS = "ns1.test.example.com,ns2.test.example.com";
const SERVICE_KEY = "acme-dns-test-service-key";

const txt = (c: string) => c.repeat(43);

describe("acme-dns input checks", () => {
  it("accepts only 43-character base64url values", () => {
    expect(isAcmeTxtValue(txt("a"))).to.equal(true);
    expect(isAcmeTxtValue("A-_" + txt("b").slice(3))).to.equal(true);
    expect(isAcmeTxtValue(txt("a").slice(1))).to.equal(false);
    expect(isAcmeTxtValue(txt("a").slice(1) + "=")).to.equal(false);
    expect(isAcmeTxtValue(42)).to.equal(false);
  });

  it("parses the httpreq fqdn of a user label only", () => {
    // another spec may set SERVER_DOMAIN in the same process: read it at run time
    const zone = userZoneName("wisera");
    expect(acmeLabelFromFqdn(`_acme-challenge.${zone}.`)).to.equal("wisera");
    expect(acmeLabelFromFqdn(`_ACME-challenge.${zone.toUpperCase()}`)).to.equal("wisera");
    expect(acmeLabelFromFqdn(`_acme-challenge.a.${zone}.`)).to.equal(null);
    expect(acmeLabelFromFqdn("_acme-challenge.wisera.other.com.")).to.equal(null);
    expect(acmeLabelFromFqdn(`${zone}.`)).to.equal(null);
  });
});

describe("acme-dns API on the PowerDNS primary", function () {
  this.timeout(30_000);
  let app: Application;
  let uid: string;
  let sig: string;
  let other: { uid: string; sig: string };
  let savedServiceKey: string | undefined;
  const ref = (id: string) => getFirestore().collection(NSL_ROUTER_COLLECTION).doc(id);

  async function zoneTxt(label: string): Promise<string[]> {
    const z = await pdns.getZone(userZoneName(label));
    const rr = z?.rrsets.find((r) => r.type === "TXT" && r.name === pdns.fqdn(`_acme-challenge.${userZoneName(label)}`));
    return (rr?.records || []).map((r) => r.content).sort();
  }

  const update = (body: object, user = uid, key = sig) =>
    request(app).post("/acme-dns/update").set("X-Api-User", user).set("X-Api-Key", key).send(body);

  before(async function () {
    if (!process.env.PDNS_API_URL) this.skip();
    savedServiceKey = process.env.SERVICE_API_KEY;
    process.env.SERVICE_API_KEY = SERVICE_KEY;
    app = createTestApp();
    uid = generateTestUserId();
    sig = await signMessage((await createTestUser(uid)).privateKey, uid);
    const otherUid = generateTestUserId();
    other = { uid: otherUid, sig: await signMessage((await createTestUser(otherUid)).privateKey, otherUid) };
  });

  beforeEach(async () => {
    await ref(uid).update({ dns: { live: true } });
    await getRedisClient().del(`acme:txt:${uid}`, `acme:rate:${uid}`);
    await dropUserZone(uid);
  });

  after(async () => {
    if (process.env.PDNS_API_URL) {
      for (const id of [uid, other?.uid].filter(Boolean)) {
        await dropUserZone(id);
        await getRedisClient().del(`acme:txt:${id}`, `acme:rate:${id}`);
        await deleteTestUser(id);
      }
      if (savedServiceKey === undefined) delete process.env.SERVICE_API_KEY;
      else process.env.SERVICE_API_KEY = savedServiceKey;
    }
    await closeRedisClient();
  });

  describe("POST /acme-dns/update", () => {
    it("sets the TXT on the primary and answers like acme-dns", async () => {
      const res = await update({ subdomain: uid, txt: txt("a") });
      expect(res.status).to.equal(200);
      expect(res.body).to.deep.equal({ txt: txt("a") });
      expect(await zoneTxt(uid)).to.deep.equal([`"${txt("a")}"`]);
    });

    it("keeps the four newest values (box and gateway may order at once)", async () => {
      for (const c of ["a", "b", "c", "d", "e"]) expect((await update({ subdomain: uid, txt: txt(c) })).status).to.equal(200);
      expect(await zoneTxt(uid)).to.deep.equal(["b", "c", "d", "e"].map((c) => `"${txt(c)}"`));
    });

    it("rejects a bad signature, a foreign subdomain or credential, a bad value", async () => {
      expect((await update({ subdomain: uid, txt: txt("a") }, uid, other.sig)).status).to.equal(401);
      expect((await update({ subdomain: uid, txt: txt("a") }, uid, "")).status).to.equal(401);
      expect((await update({ subdomain: other.uid, txt: txt("a") })).status).to.equal(403);
      expect((await update({ subdomain: uid, txt: txt("a") }, other.uid, other.sig)).status).to.equal(403);
      expect((await update({ subdomain: uid, txt: "short" })).status).to.equal(400);
      expect(await pdns.getZone(userZoneName(uid))).to.equal(null);
    });

    it("refuses a user our nameservers do not serve", async () => {
      await ref(uid).update({ dns: FieldValue.delete() });
      expect((await update({ subdomain: uid, txt: txt("a") })).status).to.equal(409);
    });

    it("rate-limits at 10 updates per hour", async () => {
      for (let i = 0; i < 10; i++) {
        expect((await update({ subdomain: uid, txt: txt(String.fromCharCode(97 + i)) })).status).to.equal(200);
      }
      expect((await update({ subdomain: uid, txt: txt("z") })).status).to.equal(429);
    });

    it("drops expired values on the next sync", async () => {
      await addAcmeTxt(uid, txt("o"), Date.now() - 11 * 60 * 1000);
      expect(await getAcmeTxt(uid)).to.deep.equal([]);
      await update({ subdomain: uid, txt: txt("n") });
      expect(await zoneTxt(uid)).to.deep.equal([`"${txt("n")}"`]);
    });
  });

  describe("POST /acme-dns/present|cleanup (lego httpreq)", () => {
    const fqdn = () => `_acme-challenge.${userZoneName(uid)}.`;
    const call = (action: string, body: object, auth = `Bearer ${SERVICE_KEY}`) =>
      request(app).post(`/acme-dns/${action}`).set("Authorization", auth).send(body);

    it("needs the service key, as Bearer or as lego's Basic password", async () => {
      expect((await call("present", { fqdn: fqdn(), value: txt("g") }, "Bearer nope")).status).to.equal(401);
      const basic = (pw: string) => `Basic ${Buffer.from(`lego:${pw}`).toString("base64")}`;
      expect((await call("present", { fqdn: fqdn(), value: txt("g") }, basic("nope"))).status).to.equal(401);
      expect((await call("present", { fqdn: fqdn(), value: txt("g") }, basic(SERVICE_KEY))).status).to.equal(200);
    });

    it("presents then cleans up a live user's challenge", async () => {
      expect((await call("present", { fqdn: fqdn(), value: txt("g") })).status).to.equal(200);
      expect(await zoneTxt(uid)).to.deep.equal([`"${txt("g")}"`]);
      expect((await call("cleanup", { fqdn: fqdn(), value: txt("g") })).status).to.equal(200);
      expect(await zoneTxt(uid)).to.deep.equal([]);
    });

    it("refuses other names and users that are not live", async () => {
      expect((await call("present", { fqdn: `_acme-challenge.x.${fqdn()}`, value: txt("g") })).status).to.equal(400);
      expect((await call("present", { fqdn: `_acme-challenge.${userZoneName(other.uid)}.`, value: txt("g") })).status).to.equal(403);
    });
  });

  describe("PUT /dns/v1/force/:userid", () => {
    const put = (body: object, as = uid, target = uid) =>
      request(app).put(`/dns/v1/force/${target}`).set("Authorization", `Bearer ${SERVICE_KEY};${as}`).send(body);

    it("lets the owner route through the gateway and back", async () => {
      const res = await put({ force: "gateway", host: "Immich" });
      expect(res.status).to.equal(200);
      expect(res.body).to.include({ force: "gateway", host: "immich" });
      expect((await ref(uid).get()).data()?.dns?.hostForce).to.deep.equal({ immich: "gateway" });
      expect((await put({ force: "gateway" })).body.answer).to.include({ kind: "gateway", reason: "forced to the gateway" });
      expect((await ref(uid).get()).data()?.dns?.force).to.equal("gateway");
      await put({ force: "auto" });
      await put({ force: "auto", host: "immich" });
      expect((await ref(uid).get()).data()?.dns).to.deep.equal({ live: true });
    });

    it("refuses direct and other users", async () => {
      expect((await put({ force: "direct" })).status).to.equal(400);
      expect((await put({ force: "gateway" }, other.uid)).status).to.equal(403);
      expect((await put({ force: "gateway", host: "a.b" })).status).to.equal(400);
    });

    it("accepts the box credential (signature route)", async () => {
      const bySig = (body: object, key = sig) => request(app).put(`/dns/v1/force/${uid}/${encodeURIComponent(key)}`).send(body);
      expect((await bySig({ force: "gateway" }, other.sig)).status).to.equal(401);
      expect((await bySig({ force: "direct" })).status).to.equal(400);
      expect((await bySig({ force: "gateway" })).body).to.include({ force: "gateway" });
      expect((await ref(uid).get()).data()?.dns?.force).to.equal("gateway");
      await bySig({ force: "auto" });
      expect((await ref(uid).get()).data()?.dns?.force).to.equal(undefined);
    });
  });

  describe("the dns block", () => {
    it("reports live (and its delegated alias) and force in /resolve/v2", async () => {
      await ref(uid).update({ "dns.hostForce": { immich: "gateway" } });
      const res = await request(app).get(`/resolve/v2/${uid}`);
      expect(res.body.dns).to.include({ delegated: true, live: true, force: "auto", answer: "gateway" });
      expect(res.body.dns.hostForce).to.deep.equal({ immich: "gateway" });
    });
  });
});
