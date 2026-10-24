import { describe, it, before, after } from "mocha";
import { expect } from "chai";
import https from "https";
import * as acme from "acme-client";
import { getRedisClient, closeRedisClient } from "../redis/redisClient.js";
import { dropUserZone, ScopeUser, userZoneName, checkLive } from "../services/DnsZones.js";
import { getAcmeTxt } from "../services/AcmeDns.js";
import { getGatewayCert, issueGatewayCert } from "../services/GatewayCerts.js";

/**
 * Gateway certificates: the backend orders <label>.<zone> + *.<label>.<zone> by DNS-01
 * against its own zone. Needs the PowerDNS primary (DNS published on PDNS_DNS_ADDR,
 * e.g. 127.0.0.1:15353) and Pebble resolving through it:
 *   docker run -d --name t-pebble -p 127.0.0.1:14000:14000 -e PEBBLE_VA_NOSLEEP=1 \
 *     -e PEBBLE_WFE_NONCEREJECT=0 ghcr.io/letsencrypt/pebble:2.9.0 \
 *     -config test/config/pebble-config.json -dnsserver <primary-ip>:53
 *   PEBBLE_URL=https://127.0.0.1:14000/dir PDNS_DNS_ADDR=127.0.0.1:15353 … npx mocha …
 * Skipped without PEBBLE_URL.
 */

process.env.SERVER_DOMAIN = process.env.SERVER_DOMAIN || "test.example.com";
process.env.DNS_GATEWAY_IPS = "192.0.2.10,192.0.2.11";
process.env.DNS_NS_HOSTS = "ns1.test.example.com,ns2.test.example.com";

describe("gateway certificates", function () {
  this.timeout(120_000);
  const user: ScopeUser = { uid: "testusergwcert", label: "gwcerttest", dns: { delegated: true } };

  it("a zone the parent does not delegate to us is not live", async () => {
    expect(await checkLive("gwcert-not-delegated-" + Date.now())).to.equal(false);
  });

  describe("issuance against Pebble", () => {
    before(async function () {
      if (!process.env.PEBBLE_URL || !process.env.PDNS_API_URL) this.skip();
      process.env.GATEWAY_ACME_DIRECTORY = process.env.PEBBLE_URL;
      // Pebble's API certificate is self-signed
      acme.axios.defaults.httpsAgent = new https.Agent({ rejectUnauthorized: false });
      await getRedisClient().del(`gwcert:${user.label}`, `acme:txt:${user.label}`, "gwcert:account");
      await dropUserZone(user.label);
    });

    after(async () => {
      if (process.env.PEBBLE_URL && process.env.PDNS_API_URL) {
        await getRedisClient().del(`gwcert:${user.label}`, `acme:txt:${user.label}`, "gwcert:account");
        await dropUserZone(user.label);
        delete process.env.GATEWAY_ACME_DIRECTORY;
      }
      await closeRedisClient();
    });

    it("orders apex + wildcard through the zone, stores it, cleans the TXT", async () => {
      const issued = await issueGatewayCert(user, { nameservers: [process.env.PDNS_DNS_ADDR || "127.0.0.1:15353"] });
      const info = acme.crypto.readCertificateInfo(issued.cert);
      const zone = userZoneName(user.label);
      expect(info.domains.altNames.sort()).to.deep.equal([`*.${zone}`, zone].sort());
      expect(new Date(issued.notAfter).getTime()).to.be.greaterThan(Date.now());
      expect(issued.key).to.contain("PRIVATE KEY");
      expect(await getGatewayCert(user.label)).to.deep.equal(issued);
      expect(await getAcmeTxt(user.label)).to.deep.equal([]);
    });
  });
});
