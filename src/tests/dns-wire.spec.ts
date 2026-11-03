import { describe, it } from "mocha";
import { expect } from "chai";
import { encodeQuery, nsFromResponse, parseResponse, TYPE_NS } from "../services/DnsWire.js";
import { missingFromParent } from "../services/DnsZones.js";
import { evaluate, ServerSample, zonesToRenotify } from "../services/DnsHealth.js";

/** The parent's own NS set (#948): the wire client, the comparison, and the health side. */

/** A referral for wisera.inojob.com from the parent: no answer, NS in authority (compressed names). */
function referral(id: number, targets: string[]): Buffer {
  const q = encodeQuery(id, "wisera.inojob.com", TYPE_NS);
  const header = Buffer.from(q.subarray(0, 12));
  header.writeUInt16BE(0x8000, 2); // QR=1, no AA (a referral), rcode 0
  header.writeUInt16BE(0, 6); // ANCOUNT
  header.writeUInt16BE(targets.length, 8); // NSCOUNT
  const question = q.subarray(12);
  const records: Buffer[] = [];
  for (const t of targets) {
    // owner: pointer to the question name (offset 12); rdata: "<first label>" + pointer to "inojob.com" (offset 12 + 7)
    const [first] = t.split(".");
    const rdata = Buffer.concat([Buffer.from([first.length]), Buffer.from(first, "ascii"), Buffer.from([0xc0, 12 + 7])]);
    const rr = Buffer.alloc(12);
    rr.writeUInt16BE(0xc00c, 0);
    rr.writeUInt16BE(TYPE_NS, 2);
    rr.writeUInt16BE(1, 4);
    rr.writeUInt32BE(300, 6);
    rr.writeUInt16BE(rdata.length, 10);
    records.push(rr, rdata);
  }
  return Buffer.concat([header, question, ...records]);
}

describe("DNS wire client (parent NS set)", () => {
  it("encodes a non-recursive NS query", () => {
    const q = encodeQuery(0x1234, "Wisera.InoJob.com.", TYPE_NS);
    expect(q.readUInt16BE(0)).to.equal(0x1234);
    expect(q.readUInt16BE(2) & 0x0100).to.equal(0); // RD off
    expect(q.readUInt16BE(4)).to.equal(1);
    expect(q.subarray(12, 12 + 19).toString("latin1")).to.equal("\x06wisera\x06inojob\x03com\x00");
    expect(q.readUInt16BE(q.length - 4)).to.equal(TYPE_NS);
  });

  it("reads the NS set of a referral, compressed names included", () => {
    const res = parseResponse(referral(7, ["nss1.inojob.com"]));
    expect(res.id).to.equal(7);
    expect(res.answers).to.have.length(0);
    expect(nsFromResponse(res, "wisera.inojob.com")).to.deep.equal(["nss1.inojob.com"]);
    expect(nsFromResponse(parseResponse(referral(8, ["nss2.inojob.com", "nss1.inojob.com"])), "WISERA.inojob.com."))
      .to.deep.equal(["nss1.inojob.com", "nss2.inojob.com"]);
  });

  it("gives null for an error code or a truncated answer, [] for no NS", () => {
    const err = referral(9, ["nss1.inojob.com"]);
    err.writeUInt16BE(0x8002, 2); // SERVFAIL
    expect(nsFromResponse(parseResponse(err), "wisera.inojob.com")).to.equal(null);
    const tc = referral(10, ["nss1.inojob.com"]);
    tc.writeUInt16BE(0x8200, 2);
    expect(nsFromResponse(parseResponse(tc), "wisera.inojob.com")).to.equal(null);
    expect(nsFromResponse(parseResponse(referral(11, [])), "wisera.inojob.com")).to.deep.equal([]);
  });

  it("rejects a malformed response", () => {
    expect(() => parseResponse(Buffer.alloc(5))).to.throw();
    expect(() => parseResponse(referral(12, ["nss1.inojob.com"]).subarray(0, 40))).to.throw();
  });

  it("names the nameservers the parent leaves out", () => {
    expect(missingFromParent(["nss1.inojob.com."], ["nss1.inojob.com", "NSS2.inojob.com"])).to.deep.equal(["nss2.inojob.com"]);
    expect(missingFromParent(["nss2.inojob.com", "nss1.inojob.com"], ["nss1.inojob.com", "nss2.inojob.com"])).to.deep.equal([]);
  });
});

describe("Nameserver catch-up and delegation in /dns/health", () => {
  const now = Date.parse("2026-11-03T16:30:00Z");
  const sample = (theirs: number | null, changedAgoMs: number | null): ServerSample => ({
    host: "nss1.inojob.com", ip: "192.0.2.1", answers: true,
    zones: [{ zone: "wisera.inojob.com.", user: true, primary: 5, theirs, changedAt: changedAgoMs === null ? null : now - changedAgoMs }],
  });

  it("NOTIFYs again a zone a nameserver is still off after a minute, or with no recent change", () => {
    expect(zonesToRenotify([sample(4, 30_000)], now)).to.deep.equal([]);
    expect(zonesToRenotify([sample(4, 90_000)], now)).to.deep.equal(["wisera.inojob.com."]);
    expect(zonesToRenotify([sample(4, null)], now)).to.deep.equal(["wisera.inojob.com."]);
    expect(zonesToRenotify([sample(5, null)], now)).to.deep.equal([]);
    expect(zonesToRenotify([{ ...sample(4, null), answers: false }], now)).to.deep.equal([]);
  });

  it("reports live zones the parent delegates to only part of the nameservers", () => {
    const ok = evaluate([sample(5, null)], true, 1, now, [], 0);
    expect(ok.status).to.equal("ok");
    expect(ok.primary.partialDelegations).to.equal(undefined);
    const partial = evaluate([sample(5, null)], true, 1, now, [], 1);
    expect(partial.status).to.equal("degraded");
    expect(partial.primary.partialDelegations).to.equal(1);
    expect(partial.problems.join()).to.match(/1 live user zone\(s\): the parent delegates to only part/);
  });
});
