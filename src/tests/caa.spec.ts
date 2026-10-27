import { describe, it } from "mocha";
import { expect } from "chai";
import { answer, caaRecords, desiredUserRRsets, isAcmeAccountUri } from "../services/DnsZones.js";

const LE = "https://acme-v02.api.letsencrypt.org/acme/acct/3328753086";
const LE2 = "https://acme-v02.api.letsencrypt.org/acme/acct/3814578606";

describe("CAA for the box's ACME accounts", () => {
  it("accepts Let's Encrypt account URIs only", () => {
    expect(isAcmeAccountUri(LE)).to.equal(true);
    expect(isAcmeAccountUri("https://acme-staging-v02.api.letsencrypt.org/acme/acct/12")).to.equal(true);
    expect(isAcmeAccountUri("https://acme.zerossl.com/v2/DV90/account/abc")).to.equal(false);
    expect(isAcmeAccountUri(`${LE}"; issue "evil.example`)).to.equal(false);
    expect(isAcmeAccountUri(`${LE}\n`)).to.equal(false);
    expect(isAcmeAccountUri(42)).to.equal(false);
  });

  it("restricts issue and issuewild to the accounts", () => {
    expect(caaRecords([LE2, LE])).to.deep.equal([
      `0 issue "letsencrypt.org; accounturi=${LE}"`,
      `0 issue "letsencrypt.org; accounturi=${LE2}"`,
      `0 issuewild "letsencrypt.org; accounturi=${LE}"`,
      `0 issuewild "letsencrypt.org; accounturi=${LE2}"`,
    ]);
  });

  it("adds an apex CAA RRset only when the box reported accounts", () => {
    const ans = answer({ publicIp: null, probe: null, gatewayIps: ["192.0.2.1"] });
    const none = desiredUserRRsets("wisera.example.com", ans, ["ns1.x"]);
    expect(none.some((r) => r.type === "CAA")).to.equal(false);
    const caa = desiredUserRRsets("wisera.example.com", ans, ["ns1.x"], [], [LE]).find((r) => r.type === "CAA");
    expect(caa?.name).to.equal("wisera.example.com.");
    expect(caa?.records.map((r) => r.content)).to.deep.equal(caaRecords([LE]));
  });
});
