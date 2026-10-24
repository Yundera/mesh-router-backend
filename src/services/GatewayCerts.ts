import { promises as dnsp } from "dns";
import * as acme from "acme-client";
import { getRedisClient } from "../redis/redisClient.js";
import { getDnsNsHosts } from "../configuration/config.js";
import { addAcmeTxt, removeAcmeTxt } from "./AcmeDns.js";
import { delegatedUsers, isLive, isUserZonesEnabled, ScopeUser, syncUser, userZoneName } from "./DnsZones.js";

/**
 * Certificates the gateways serve for delegated users' names (<label>.<zone> and
 * *.<label>.<zone>): when our nameservers answer the gateway (box offline, forced, or
 * before its own cert), browsers reach a gateway directly, without Cloudflare in front.
 * The backend owns the zone, so it does DNS-01 itself (writes the TXT through the same
 * store as the acme-dns API); every gateway fetches the result from GET /gateway/cert.
 * Off unless GATEWAY_ACME_DIRECTORY is set.
 */

/** Renew when fewer days than this remain. */
const RENEW_BEFORE_MS = 30 * 24 * 60 * 60 * 1000;
/** After a failed order, wait this long before the next try for that user. */
const FAILURE_BACKOFF_SECONDS = 60 * 60;
/** How long a challenge value may take to show on every nameserver. */
const PROPAGATION_TIMEOUT_MS = 60_000;
const PASS_INTERVAL_MS = 5 * 60 * 1000;

export interface GatewayCert {
  cert: string;
  key: string;
  notAfter: string;
}

export function isGatewayCertsEnabled(): boolean {
  return !!process.env.GATEWAY_ACME_DIRECTORY && isUserZonesEnabled();
}

function certKey(label: string): string {
  return `gwcert:${label.toLowerCase()}`;
}

function failKey(label: string): string {
  return `gwcert:fail:${label.toLowerCase()}`;
}

export async function getGatewayCert(label: string): Promise<GatewayCert | null> {
  const raw = await getRedisClient().get(certKey(label));
  if (!raw) return null;
  try {
    return JSON.parse(raw) as GatewayCert;
  } catch {
    return null;
  }
}

/** The ACME client, with an account key kept in Redis so restarts reuse the account. */
async function acmeClient(): Promise<acme.Client> {
  const redis = getRedisClient();
  let accountKey = await redis.get("gwcert:account");
  if (!accountKey) {
    accountKey = (await acme.crypto.createPrivateEcdsaKey()).toString();
    await redis.set("gwcert:account", accountKey);
  }
  return new acme.Client({ directoryUrl: process.env.GATEWAY_ACME_DIRECTORY as string, accountKey });
}

/** Addresses ("ip" or "ip:port") of the DNS_NS_HOSTS. */
async function nameserverAddresses(): Promise<string[]> {
  const ips = (await Promise.all(getDnsNsHosts().map((h) => dnsp.resolve4(h).catch(() => [] as string[])))).flat();
  if (ips.length === 0) throw new Error(`no address for the nameservers ${getDnsNsHosts().join(",")}`);
  return ips;
}

/** Wait until every nameserver serves `value` at `name` (the CA asks them directly). */
async function waitForTxt(name: string, value: string, ips: string[]): Promise<void> {
  const deadline = Date.now() + PROPAGATION_TIMEOUT_MS;
  for (const ip of ips) {
    const resolver = new dnsp.Resolver({ timeout: 2000, tries: 1 });
    resolver.setServers([ip]);
    for (;;) {
      const txt = await resolver.resolveTxt(name).catch(() => [] as string[][]);
      if (txt.some((chunks) => chunks.join("") === value)) break;
      if (Date.now() > deadline) throw new Error(`${name} TXT not on ${ip} after ${PROPAGATION_TIMEOUT_MS / 1000}s`);
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
}

/**
 * Order <label>.<zone> + *.<label>.<zone> by DNS-01 and store it. `nameservers`
 * ("ip[:port]") overrides the addresses of DNS_NS_HOSTS checked before validation.
 */
export async function issueGatewayCert(user: ScopeUser, options: { nameservers?: string[] } = {}): Promise<GatewayCert> {
  const zone = userZoneName(user.label);
  const nameservers = options.nameservers ?? await nameserverAddresses();
  const client = await acmeClient();
  const [key, csr] = await acme.crypto.createCsr({ commonName: zone, altNames: [zone, `*.${zone}`] },
    await acme.crypto.createPrivateEcdsaKey());
  const cert = await client.auto({
    csr,
    email: process.env.GATEWAY_ACME_EMAIL || undefined,
    termsOfServiceAgreed: true,
    challengePriority: ["dns-01"],
    // our own check below asks the authoritative servers; the client's would use recursion
    skipChallengeVerification: true,
    challengeCreateFn: async (_authz, _challenge, value) => {
      await addAcmeTxt(user.label, value);
      await syncUser(user);
      await waitForTxt(`_acme-challenge.${zone}`, value, nameservers);
    },
    challengeRemoveFn: async (_authz, _challenge, value) => {
      await removeAcmeTxt(user.label, value);
      await syncUser(user);
    },
  });
  const info = acme.crypto.readCertificateInfo(cert);
  const stored: GatewayCert = { cert, key: key.toString(), notAfter: info.notAfter.toISOString() };
  await getRedisClient().set(certKey(user.label), JSON.stringify(stored));
  console.log(`[gwcert] ${user.label}: ${zone} + *.${zone} issued, notAfter ${stored.notAfter}`);
  return stored;
}

/** True when the user needs a (new) certificate now. */
async function due(user: ScopeUser, now = Date.now()): Promise<boolean> {
  if (!(await isLive(user.label))) return false;
  if (await getRedisClient().exists(failKey(user.label))) return false;
  const current = await getGatewayCert(user.label);
  return !current || new Date(current.notAfter).getTime() - now < RENEW_BEFORE_MS;
}

/** One pass: issue or renew for every live delegated user, one order at a time. */
export async function syncGatewayCerts(): Promise<{ issued: string[]; failed: string[] }> {
  const result = { issued: [] as string[], failed: [] as string[] };
  for (const user of await delegatedUsers()) {
    if (!(await due(user))) continue;
    try {
      await issueGatewayCert(user);
      result.issued.push(user.label);
    } catch (e) {
      result.failed.push(user.label);
      await getRedisClient().setex(failKey(user.label), FAILURE_BACKOFF_SECONDS, String((e as Error).message ?? e));
      console.error(`[gwcert] ${user.label}: order failed, next try in 1h: ${(e as Error).message ?? e}`);
    }
  }
  return result;
}

let timer: NodeJS.Timeout | null = null;

export function startGatewayCerts(intervalMs = PASS_INTERVAL_MS): void {
  if (!isGatewayCertsEnabled() || timer) return;
  let running = false;
  const pass = async () => {
    if (running) return;
    running = true;
    try {
      await syncGatewayCerts();
    } catch (e) {
      console.error(`[gwcert] pass failed: ${(e as Error).message ?? e}`);
    } finally {
      running = false;
    }
  };
  // after the first DNS pass has had time to fill the scope and the live checks
  setTimeout(pass, 90_000);
  timer = setInterval(pass, intervalMs);
  console.log(`[gwcert] gateway certificates on: ${process.env.GATEWAY_ACME_DIRECTORY}`);
}

export function stopGatewayCerts(): void {
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
}
