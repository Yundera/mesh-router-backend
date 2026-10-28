import { describe, it } from "mocha";
import { expect } from "chai";
import { evaluate, httpStatusFor, ServerSample, ZoneSample } from "../services/DnsHealth.js";

/** The nameserver health verdict (GET /dns/health). Pure: no DNS, no PowerDNS. */

const MIN = 60 * 1000;

function zones(theirs: Partial<Record<string, number | null>> = {}, changedAt: number | null = null): ZoneSample[] {
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
    changedAt,
  }));
}

function ns(host: string, ip: string | null, z: ZoneSample[] = zones(), answers = true): ServerSample {
  return { host, ip, answers, zones: answers ? z : [] };
}

const NOW = 100 * MIN;

describe("DNS health verdict", () => {
  it("degraded while a gateway is down, which is named", () => {
    const up = { ip: "192.0.2.10", up: true, streak: 0 };
    const down = { ip: "192.0.2.11", up: false, streak: 0, lastError: "timeout", changedAt: "2026-10-28T10:00:00.000Z" };
    const h = evaluate([ns("nss1", "192.0.2.1")], true, 3, NOW, [up, down]);
    expect(h.status).to.equal("degraded");
    expect(h.gateways.map((g) => g.up)).to.deep.equal([true, false]);
    expect(h.problems).to.deep.equal(["gateway 192.0.2.11 down since 2026-10-28T10:00:00.000Z: timeout (out of the answers)"]);
    expect(evaluate([ns("nss1", "192.0.2.1")], true, 3, NOW, [up]).status).to.equal("ok");
  });

  it("ok when every nameserver answers at the primary's serials", () => {
    const h = evaluate([ns("nss1", "192.0.2.1"), ns("nss2", "192.0.2.2")], true, 3, NOW);
    expect(h.status).to.equal("ok");
    expect(h.problems).to.deep.equal([]);
    expect(httpStatusFor(h.status)).to.equal(200);
  });

  it("reports a zone a nameserver never received on the first check", () => {
    // nsp1 on 2026-10-26: no transfer ever, the primary unchanged for hours
    const none = { "catalog.test.example.com.invalid.": null, "allow.ip.test.example.com.invalid.": null };
    const h = evaluate([ns("nss1", "192.0.2.1", zones(none)), ns("nss2", "192.0.2.2")], true, 3, NOW);
    expect(h.status).to.equal("degraded");
    expect(h.nameservers[0].missing).to.deep.equal(["catalog.test.example.com.invalid.", "allow.ip.test.example.com.invalid."]);
    expect(h.nameservers[0].behind).to.deep.equal([]);
    expect(h.problems[0]).to.contain("does not serve");
    expect(httpStatusFor(h.status)).to.equal(500);
  });

  it("counts the grace from the primary's change, not from the first check", () => {
    const behind = (changedAt: number | null) =>
      [ns("nss1", "192.0.2.1", zones({ "catalog.test.example.com.invalid.": 9 }, changedAt)), ns("nss2", "192.0.2.2")];
    const fresh = evaluate(behind(NOW - 4 * MIN), true, 3, NOW);
    expect(fresh.status).to.equal("ok");
    expect(fresh.nameservers[0].pending).to.equal(1);
    const late = evaluate(behind(NOW - 6 * MIN), true, 3, NOW);
    expect(late.status).to.equal("degraded");
    expect(late.nameservers[0].behind).to.deep.equal(["catalog.test.example.com.invalid."]);
    expect(late.nameservers[0].pending).to.equal(0);
    expect(evaluate(behind(null), true, 3, NOW).status).to.equal("degraded");
  });

  it("a zone just created is pending, not missing", () => {
    const h = evaluate([ns("nss1", "192.0.2.1", zones({ "alice.test.example.com.": null }, NOW - MIN))], true, 3, NOW);
    expect(h.status).to.equal("ok");
    expect(h.nameservers[0].missingUserZones).to.equal(0);
  });

  it("counts user zones without naming them", () => {
    const h = evaluate([ns("nss1", "192.0.2.1", zones({ "alice.test.example.com.": null }))], true, 3, NOW);
    expect(h.nameservers[0].missing).to.deep.equal([]);
    expect(h.nameservers[0].missingUserZones).to.equal(1);
    const b = evaluate([ns("nss1", "192.0.2.1", zones({ "alice.test.example.com.": 29 }))], true, 3, NOW);
    expect(b.nameservers[0].behindUserZones).to.equal(1);
    expect(JSON.stringify(h) + JSON.stringify(b)).not.to.contain("alice");
  });

  it("degraded when one nameserver is down, down when none answers", () => {
    const one = evaluate([ns("nss1", "192.0.2.1", [], false), ns("nss2", "192.0.2.2")], true, 3, NOW);
    expect(one.status).to.equal("degraded");
    const none = evaluate([ns("nss1", "192.0.2.1", [], false), ns("nss2", null)], true, 3, NOW);
    expect(none.status).to.equal("down");
    expect(httpStatusFor(none.status)).to.equal(503);
  });

  it("degraded when the primary is unreachable", () => {
    const h = evaluate([ns("nss1", "192.0.2.1", [])], false, 0, NOW);
    expect(h.status).to.equal("degraded");
    expect(h.problems[0]).to.contain("primary");
  });
});
