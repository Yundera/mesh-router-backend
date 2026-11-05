import { describe, it } from "mocha";
import { expect } from "chai";
import { answer, caaRecords, desiredUserRRsets, isAcmeAccountUri } from "../services/DnsZones.js";
import { getCaaGatewayIssuers } from "../configuration/config.js";

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

  it("adds the gateways' issuers next to the box's accounts, never alone", () => {
    const gw = ["sectigo.com", `letsencrypt.org; accounturi=${LE2}`];
    expect(caaRecords([], gw)).to.deep.equal([]);
    expect(caaRecords([LE, LE2], gw)).to.deep.equal([
      `0 issue "letsencrypt.org; accounturi=${LE}"`,
      `0 issue "letsencrypt.org; accounturi=${LE2}"`,
      `0 issue "sectigo.com"`,
      `0 issuewild "letsencrypt.org; accounturi=${LE}"`,
      `0 issuewild "letsencrypt.org; accounturi=${LE2}"`,
      `0 issuewild "sectigo.com"`,
    ]);
  });

  it("reads DNS_CAA_GATEWAY_ISSUERS, skipping malformed entries", () => {
    const before = process.env.DNS_CAA_GATEWAY_ISSUERS;
    try {
      process.env.DNS_CAA_GATEWAY_ISSUERS = ` sectigo.com | letsencrypt.org ;accounturi=${LE} | evil"; issue "x | `;
      expect(getCaaGatewayIssuers()).to.deep.equal(["sectigo.com", `letsencrypt.org; accounturi=${LE}`]);
      delete process.env.DNS_CAA_GATEWAY_ISSUERS;
      expect(getCaaGatewayIssuers()).to.deep.equal([]);
    } finally {
      if (before === undefined) delete process.env.DNS_CAA_GATEWAY_ISSUERS;
      else process.env.DNS_CAA_GATEWAY_ISSUERS = before;
    }
  });
});
