import { describe, it } from "mocha";
import { expect } from "chai";
import { normalizeRoute } from "../services/RouteValidator.js";

const tunnel = { ip: "10.77.0.100", port: 80, priority: 2, source: "tunnel", scheme: "https" };

describe("route input (POST /routes body)", () => {
  it("keeps tunnelIp on a tunnel route", () => {
    expect(normalizeRoute({ ...tunnel, tunnelIp: "10.78.0.6" }, 0)).to.deep.equal({ ...tunnel, tunnelIp: "10.78.0.6" });
  });

  it("rejects tunnelIp on a non-tunnel route or outside private IPv4", () => {
    for (const route of [
      { ...tunnel, source: "agent", port: 443, priority: 1, tunnelIp: "10.78.0.6" },
      { ...tunnel, tunnelIp: "203.0.113.5" },
      { ...tunnel, tunnelIp: "127.0.0.1" },
      { ...tunnel, tunnelIp: "fd00::1" },
      { ...tunnel, tunnelIp: 42 },
    ]) {
      expect(() => normalizeRoute(route, 3)).to.throw("Route 3: tunnelIp must be a private IPv4");
    }
  });

  it("keeps only known fields", () => {
    const r = normalizeRoute({ ...tunnel, type: "domain", domain: "1-2-3-4.ip.example.com", extra: "x" }, 0);
    expect(r).to.deep.equal({ ...tunnel, type: "domain", domain: "1-2-3-4.ip.example.com" });
  });

  it("rejects missing or invalid basics", () => {
    expect(() => normalizeRoute({ ...tunnel, port: 99999 }, 0)).to.throw("port must be between 1 and 65535");
    expect(() => normalizeRoute({ ...tunnel, ip: "" }, 0)).to.throw("ip is required");
    expect(() => normalizeRoute({ ...tunnel, priority: "1" }, 0)).to.throw("priority is required");
    expect(() => normalizeRoute({ ...tunnel, scheme: "ftp" }, 0)).to.throw('scheme must be "http" or "https"');
    expect(() => normalizeRoute({ ...tunnel, type: "domain" }, 0)).to.throw("domain is required");
  });
});
