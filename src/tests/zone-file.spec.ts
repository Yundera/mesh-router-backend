import { describe, it } from "mocha";
import { expect } from "chai";
import { parseZoneFile, ZoneFileError } from "../services/ZoneFile.js";
import { desiredApexRRsets } from "../services/DnsZones.js";

/** The static zone file of SERVER_DOMAIN and the apex zone built from it. Pure: no services. */

process.env.SERVER_DOMAIN = process.env.SERVER_DOMAIN || "test.example.com";

const ZONE = "test.example.com";

function errorsOf(fn: () => unknown): string[] {
  try {
    fn();
  } catch (e) {
    if (e instanceof ZoneFileError) return e.errors;
    throw e;
  }
  return [];
}

describe("zone file parser", () => {
  it("reads a Cloudflare export: absolute names, TTL then class, comments, SOA dropped", () => {
    const records = parseZoneFile([
      ";; SOA Record",
      "test.example.com\t3600\tIN\tSOA\tjulian.ns.cloudflare.com. dns.cloudflare.com. 2054460337 10000 2400 604800 3600",
      "nss1.test.example.com.\t300\tIN\tA\t51.15.79.231 ; nameserver cf_tags=cf-proxied:false",
      "em4808.test.example.com.\t300\tIN\tCNAME\tu49916735.wl236.sendgrid.net. ; sendgrid",
      "_dmarc.test.example.com.\t300\tIN\tTXT\t\"v=DMARC1; p=none;\" ; sendgrid",
    ].join("\n"), ZONE);
    expect(records.map((r) => [r.name, r.ttl, r.type, r.content])).to.deep.equal([
      ["nss1.test.example.com.", 300, "A", "51.15.79.231"],
      ["em4808.test.example.com.", 300, "CNAME", "u49916735.wl236.sendgrid.net."],
      ["_dmarc.test.example.com.", 300, "TXT", "\"v=DMARC1; p=none;\""],
    ]);
  });

  it("handles $TTL, $ORIGIN, @, relative names, a blank owner and parentheses", () => {
    const records = parseZoneFile([
      "$TTL 1h",
      "@ IN A 151.115.97.163",
      "  MX 10 mx1",
      "  TXT \"v=spf1 include:sendgrid.net ~all\" \"second\"",
      "@ CAA ( 0 issue",
      "        \"letsencrypt.org\" )",
      "$ORIGIN _tcp.test.example.com.",
      "_sip 600 SRV 10 5 5060 sip.test.example.com.",
    ].join("\n"), ZONE);
    expect(records.map((r) => [r.name, r.ttl, r.type, r.content])).to.deep.equal([
      ["test.example.com.", 3600, "A", "151.115.97.163"],
      ["test.example.com.", 3600, "MX", "10 mx1.test.example.com."],
      ["test.example.com.", 3600, "TXT", "\"v=spf1 include:sendgrid.net ~all\" \"second\""],
      ["test.example.com.", 3600, "CAA", "0 issue \"letsencrypt.org\""],
      ["_sip._tcp.test.example.com.", 600, "SRV", "10 5 5060 sip.test.example.com."],
    ]);
  });

  it("defaults the TTL to 300", () => {
    expect(parseZoneFile("www A 1.2.3.4", ZONE)[0].ttl).to.equal(300);
  });

  it("collects every error with its line", () => {
    const errors = errorsOf(() => parseZoneFile([
      "www A 1.2.3",
      "other.example.org. A 1.2.3.4",
      "x PTR host.",
      "$INCLUDE other.zone",
      "y TXT \"open",
    ].join("\n"), ZONE));
    expect(errors).to.have.length(5);
    for (const want of [/^line 1: not an IPv4/, /^line 2: .*outside the zone/, /^line 3: unsupported type/,
      /^line 4: unsupported directive/, /^line 5: unterminated/]) {
      expect(errors.some((e) => want.test(e)), String(want)).to.equal(true);
    }
  });
});

describe("apex zone", () => {
  const base = {
    zone: ZONE,
    nsHosts: ["nss2.test.example.com", "nss1.test.example.com"],
    gatewayIps: ["151.115.96.14", "51.15.79.231"],
    ipZone: "ip.test.example.com",
    delegated: ["wisera"],
  };

  it("adds apex NS, the gateway wildcard and the delegations to the file's records", () => {
    const records = parseZoneFile("@ A 151.115.97.163\nnss1 A 51.15.79.231", ZONE);
    const { rrsets, skipped } = desiredApexRRsets({ ...base, records });
    const view = rrsets.map((r) => `${r.name} ${r.type} ${r.records.map((x) => x.content).join(",")}`);
    expect(view).to.deep.equal([
      "test.example.com. NS nss1.test.example.com.,nss2.test.example.com.",
      "*.test.example.com. A 151.115.96.14,51.15.79.231",
      "ip.test.example.com. NS nss1.test.example.com.,nss2.test.example.com.",
      "wisera.test.example.com. NS nss1.test.example.com.,nss2.test.example.com.",
      "test.example.com. A 151.115.97.163",
      "nss1.test.example.com. A 51.15.79.231",
    ]);
    expect(skipped).to.deep.equal([]);
  });

  it("leaves out what the backend owns and what sits under a delegation", () => {
    const records = parseZoneFile([
      "@ NS ns.cloudflare.com.",
      "* A 1.1.1.1",
      "ip NS other.",
      "x.wisera A 1.2.3.4",
      "* MX 10 mail",
    ].join("\n"), ZONE);
    const { rrsets, skipped } = desiredApexRRsets({ ...base, records });
    expect(skipped).to.have.length(4);
    expect(rrsets.find((r) => r.name === "*.test.example.com." && r.type === "MX")).to.not.equal(undefined);
  });

  it("merges records of one RRset under the lowest TTL", () => {
    const records = parseZoneFile("@ 3600 MX 10 a.\n@ 300 MX 20 b.\n@ 300 MX 20 b.", ZONE);
    const mx = desiredApexRRsets({ ...base, records }).rrsets.find((r) => r.type === "MX")!;
    expect(mx.ttl).to.equal(300);
    expect(mx.records.map((r) => r.content)).to.deep.equal(["10 a.", "20 b."]);
  });

  it("refuses a CNAME beside other data", () => {
    const records = parseZoneFile("www CNAME a.\nwww TXT \"x\"", ZONE);
    expect(errorsOf(() => desiredApexRRsets({ ...base, records }))).to.have.length(1);
  });

  it("skips the ip.<zone> delegation when the ip zone is elsewhere, and the wildcard without gateways", () => {
    const { rrsets } = desiredApexRRsets({ ...base, records: [], ipZone: "ip.other.org", gatewayIps: [], delegated: [] });
    expect(rrsets.map((r) => `${r.name} ${r.type}`)).to.deep.equal(["test.example.com. NS"]);
  });
});
