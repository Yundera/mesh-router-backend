import { describe, it } from "mocha";
import { expect } from "chai";
import { evaluate, httpStatusFor, ServerSample, ZoneSample } from "../services/DnsHealth.js";

/** The nameserver health verdict (GET /dns/health). Pure: no DNS, no PowerDNS. */

const MIN = 60 * 1000;

function zones(theirs: Partial<Record<string, number | null>> = {}): ZoneSample[] {
  const primary: Record<string, number> = {
    "catalog.test.example.com.invalid.": 10,
    "allow.ip.test.example.com.invalid.": 20,
    "alice.test.example.com.": 30,
  };
  return Object.entries(primary).map(([zone, serial]) => ({
    zone,
    user: !zone.endsWith(".invalid."),
    primary: serial,
    theirs: zone in theirs ? (theirs[zone] as number | null) : serial,
  }));
}

function ns(host: string, ip: string | null, z: ZoneSample[] = zones(), answers = true): ServerSample {
  return { host, ip, answers, zones: answers ? z : [] };
}

describe("DNS health verdict", () => {
  it("ok when every nameserver answers at the primary's serials", () => {
    const h = evaluate([ns("nss1", "192.0.2.1"), ns("nss2", "192.0.2.2")], true, 3, 0, new Map());
    expect(h.status).to.equal("ok");
    expect(h.problems).to.deep.equal([]);
    expect(httpStatusFor(h.status)).to.equal(200);
  });

  it("tolerates a lag shorter than the grace, reports it past the grace", () => {
    const lag = new Map<string, number>();
    const behind = () => [ns("nss1", "192.0.2.1", zones({ "catalog.test.example.com.invalid.": 9 })), ns("nss2", "192.0.2.2")];
    expect(evaluate(behind(), true, 3, 0, lag).status).to.equal("ok");
    expect(evaluate(behind(), true, 3, 4 * MIN, lag).status).to.equal("ok");
    const h = evaluate(behind(), true, 3, 6 * MIN, lag);
    expect(h.status).to.equal("degraded");
    expect(h.nameservers[0].behind).to.deep.equal(["catalog.test.example.com.invalid."]);
    expect(httpStatusFor(h.status)).to.equal(500);
  });

  it("forgets the lag once back in sync", () => {
    const lag = new Map<string, number>();
    evaluate([ns("nss1", "192.0.2.1", zones({ "alice.test.example.com.": 29 }))], true, 3, 0, lag);
    evaluate([ns("nss1", "192.0.2.1")], true, 3, 3 * MIN, lag);
    expect(lag.size).to.equal(0);
    const h = evaluate([ns("nss1", "192.0.2.1", zones({ "alice.test.example.com.": 30 }))], true, 3, 10 * MIN, lag);
    expect(h.status).to.equal("ok");
  });

  it("counts user zones without naming them", () => {
    const lag = new Map<string, number>([["192.0.2.1|alice.test.example.com.", 0]]);
    const h = evaluate([ns("nss1", "192.0.2.1", zones({ "alice.test.example.com.": null }))], true, 3, 10 * MIN, lag);
    expect(h.nameservers[0].behind).to.deep.equal([]);
    expect(h.nameservers[0].behindUserZones).to.equal(1);
    expect(JSON.stringify(h)).not.to.contain("alice");
  });

  it("degraded when one nameserver is down, down when none answers", () => {
    const one = evaluate([ns("nss1", "192.0.2.1", [], false), ns("nss2", "192.0.2.2")], true, 3, 0, new Map());
    expect(one.status).to.equal("degraded");
    const none = evaluate([ns("nss1", "192.0.2.1", [], false), ns("nss2", null)], true, 3, 0, new Map());
    expect(none.status).to.equal("down");
    expect(httpStatusFor(none.status)).to.equal(503);
  });

  it("degraded when the primary is unreachable", () => {
    const h = evaluate([ns("nss1", "192.0.2.1", [])], false, 0, 0, new Map());
    expect(h.status).to.equal("degraded");
    expect(h.problems[0]).to.contain("primary");
  });
});
