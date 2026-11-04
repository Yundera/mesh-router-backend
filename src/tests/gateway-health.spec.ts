import { describe, it } from "mocha";
import { expect } from "chai";
import * as net from "net";
import * as http from "http";
import { checkGateway, checkProvider, GatewayCert, gatewayCertProblem, GatewayState, inSubnet, nextState, pickForBox, pickHealthy, routesForGateways, toGatewayCert } from "../services/GatewayHealth.js";
import type { PeerCertificate } from "tls";
import { gatewayCertName } from "../services/CertificateAuthority.js";

/** Gateway health: FALL/RISE hysteresis, fail-open answer set, the handshake check. */

const T = new Date("2026-10-28T10:00:00Z");

function run(results: boolean[]): GatewayState {
  return results.reduce((s, ok) => nextState(s, ok, ok ? undefined : "timeout", T), { ip: "192.0.2.10", up: true, streak: 0 } as GatewayState);
}

describe("Gateway health", () => {
  it("goes down after two failed checks in a row, not one", () => {
    expect(run([false]).up).to.equal(true);
    expect(run([false, true, false]).up).to.equal(true);
    const down = run([false, false]);
    expect(down.up).to.equal(false);
    expect(down.changedAt).to.equal(T.toISOString());
    expect(down.lastError).to.equal("timeout");
  });

  it("comes back after two good checks in a row", () => {
    expect(run([false, false, true]).up).to.equal(false);
    expect(run([false, false, true, false, true]).up).to.equal(false);
    const back = run([false, false, true, true]);
    expect(back.up).to.equal(true);
    expect(back.lastError).to.equal(undefined);
  });

  it("answers the healthy gateways, and all of them when none is", () => {
    const ips = ["192.0.2.10", "192.0.2.11"];
    expect(pickHealthy(ips, (ip) => ip !== "192.0.2.11")).to.deep.equal(["192.0.2.10"]);
    expect(pickHealthy(ips, () => false)).to.deep.equal(ips);
    expect(pickHealthy([], () => true)).to.deep.equal([]);
  });

  it("reports a gateway that accepts TCP but never finishes TLS, and a closed port", async function () {
    this.timeout(10_000);
    const server = net.createServer((sock) => sock.end()); // closes before any TLS
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as net.AddressInfo).port;
    try {
      expect(await checkGateway("127.0.0.1", port, "gateway.entrypoint.test.example")).to.be.a("string");
    } finally {
      server.close();
    }
    expect(await checkGateway("127.0.0.1", port, "gateway.entrypoint.test.example")).to.be.a("string");
  });

  it("reads the certificate a gateway presents", () => {
    const le = toGatewayCert({
      valid_to: "Feb  2 09:28:19 2027 GMT",
      issuer: { C: "US", O: "Let's Encrypt", CN: "YE1" },
      subject: { CN: "*.test.example.com" },
      subjectaltname: "DNS:*.test.example.com",
    } as unknown as PeerCertificate)!;
    expect(le).to.deep.equal({ notAfter: "2027-02-02T09:28:19.000Z", issuer: "Let's Encrypt, YE1", names: ["*.test.example.com"], selfSigned: false });
    const own = toGatewayCert({
      valid_to: "Oct 30 10:00:00 2036 GMT", issuer: { CN: "mesh-router-gateway" }, subject: { CN: "mesh-router-gateway" },
    } as unknown as PeerCertificate)!;
    expect(own.selfSigned).to.equal(true);
    expect(own.names).to.deep.equal([]);
    expect(toGatewayCert({} as PeerCertificate)).to.equal(undefined);
  });

  it("judges the gateway certificate only with a minimum set", () => {
    const now = new Date("2026-11-04T10:00:00Z");
    const cert = (over: Partial<GatewayCert>): GatewayCert => ({
      notAfter: "2027-02-02T09:28:19.000Z", issuer: "Let's Encrypt, YE1", names: ["*.test.example.com"], selfSigned: false, ...over,
    });
    expect(gatewayCertProblem(cert({ selfSigned: true }), "test.example.com", 0, now)).to.equal(null);
    expect(gatewayCertProblem(cert({}), "test.example.com", 14, now)).to.equal(null);
    expect(gatewayCertProblem(undefined, "test.example.com", 14, now)).to.equal(null);
    expect(gatewayCertProblem(cert({ selfSigned: true }), "test.example.com", 14, now)).to.match(/self-signed/);
    expect(gatewayCertProblem(cert({ names: ["*.other.org"] }), "test.example.com", 14, now)).to.match(/does not name \*\.test\.example\.com/);
    expect(gatewayCertProblem(cert({ notAfter: "2026-11-14T10:00:00.000Z" }), "test.example.com", 14, now)).to.match(/10 days left/);
  });

  it("matches tunnel addresses to subnets", () => {
    expect(inSubnet("10.79.0.4", "10.79.0.0/16")).to.equal(true);
    expect(inSubnet("10.78.255.1", "10.79.0.0/16")).to.equal(false);
    expect(inSubnet("10.79.0.4", "10.79.0.4/32")).to.equal(true);
    expect(inSubnet("not-an-ip", "10.79.0.0/16")).to.equal(false);
  });

  describe("gateways for a NAT box", () => {
    const G1 = "192.0.2.10";
    const G2 = "192.0.2.11";
    const tunnels = [{ ip: G1, subnet: "10.78.0.0/16" }, { ip: G2, subnet: "10.79.0.0/16" }];
    const allUp = () => true;

    it("answers only the gateways whose provider the box is connected to", () => {
      expect(pickForBox([G1, G2], tunnels, allUp, ["10.78.0.4"])).to.deep.equal([G1]); // tunnel < 1.5.0
      expect(pickForBox([G1, G2], tunnels, allUp, ["10.78.0.4", "10.79.0.7"])).to.deep.equal([G1, G2]);
    });

    it("drops a gateway whose provider is down, unless no reaching gateway is left", () => {
      expect(pickForBox([G1, G2], tunnels, (ip) => ip !== G2, ["10.78.0.4", "10.79.0.7"])).to.deep.equal([G1]);
      expect(pickForBox([G1, G2], tunnels, () => false, ["10.78.0.4", "10.79.0.7"])).to.deep.equal([G1, G2]);
    });

    it("leaves out an unhealthy gateway even when it reaches the box", () => {
      expect(pickForBox([G2], tunnels, allUp, ["10.78.0.4", "10.79.0.7"])).to.deep.equal([G2]);
    });

    it("falls back to every healthy gateway when nothing matches", () => {
      expect(pickForBox([G1, G2], [], allUp, ["10.78.0.4"])).to.deep.equal([G1, G2]); // no mapping
      expect(pickForBox([G1, G2], tunnels, allUp, [])).to.deep.equal([G1, G2]); // no tunnelIp
      expect(pickForBox([G1, G2], tunnels, allUp, ["10.99.0.1"])).to.deep.equal([G1, G2]); // unknown subnet
      expect(pickForBox([G2], tunnels, allUp, ["10.78.0.4"])).to.deep.equal([G2]); // reaching gateway unhealthy
    });
  });

  it("checks a provider's /api/ping", async function () {
    this.timeout(10_000);
    const server = http.createServer((req, res) => {
      res.statusCode = req.url === "/api/ping" ? 200 : 404;
      res.end("ok");
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as net.AddressInfo).port;
    try {
      expect(await checkProvider(`http://127.0.0.1:${port}`)).to.equal(undefined);
      expect(await checkProvider(`http://127.0.0.1:${port}/x`)).to.equal("status 404");
    } finally {
      server.close();
    }
    expect(await checkProvider(`http://127.0.0.1:${port}`)).to.be.a("string");
  });
  describe("routes handed to the gateways (handoff)", () => {
    const G1 = "192.0.2.10", G2 = "192.0.2.11";
    const tunnels = [{ ip: G1, subnet: "10.78.0.0/16" }, { ip: G2, subnet: "10.79.0.0/16" }];
    const agent = { source: "agent", ip: "203.0.113.5" };
    const t1 = { source: "tunnel", ip: "172.30.0.3", tunnelIp: "10.78.0.4" };
    const t2 = { source: "tunnel", ip: "172.31.0.3", tunnelIp: "10.79.0.7" };
    const legacy = { source: "tunnel", ip: "172.30.0.3" };

    it("tags each tunnel route with the gateway whose subnet holds it", () => {
      const out = routesForGateways([agent, t1, t2, legacy], tunnels, () => true);
      expect(out.map((r) => r.gateway)).to.deep.equal([undefined, G1, G2, undefined]);
    });

    it("drops the routes of a dead provider, but never all tagged ones", () => {
      expect(routesForGateways([t1, t2], tunnels, (ip) => ip !== G2).map((r) => r.gateway)).to.deep.equal([G1]);
      expect(routesForGateways([agent, t2], tunnels, (ip) => ip !== G2).map((r) => r.gateway)).to.deep.equal([undefined, G2]);
      expect(routesForGateways([t1, t2], tunnels, () => false)).to.have.length(2);
    });

    it("changes nothing without a tunnel mapping", () => {
      expect(routesForGateways([agent, t1], [], () => false)).to.deep.equal([agent, t1]);
    });

    it("names a gateway certificate under the reserved gw label", () => {
      expect(gatewayCertName("51.15.79.231", "InoJob.com")).to.equal("51-15-79-231.gw.inojob.com");
    });
  });
});
