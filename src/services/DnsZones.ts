import { isIPv4, isIPv6 } from "net";
import { getRedisClient } from "../redis/redisClient.js";
import {
  getDnsAllowGraceSeconds,
  getDnsCatalogZone,
  getDnsIpZone,
  getPdnsApiUrl,
} from "../configuration/config.js";
import { isLanOrReserved } from "./Probe.js";
import { Route } from "./Routes.js";
import * as pdns from "./PowerDns.js";

/**
 * Backend side of the nameserver (mesh-router-nameserver docs/architecture.md §10):
 * the backend is the only writer of the PowerDNS hidden primary; the public
 * secondaries follow by NOTIFY + AXFR, catalog zone included.
 *
 * Implemented so far: the ip.<zone> allowlist. ip.<zone> itself is a local Lua zone
 * on each secondary that answers an IP only if allow.<ip-zone>.invalid holds
 * <key> A|AAAA <ip> — key = dashed IPv4 or 32-digit expanded IPv6. This file keeps
 * that zone equal to the public IPs agents registered within the grace period.
 */

/** Redis sorted set: IP → last time an agent registered it (ms). */
const ALLOW_KEY = "dns:allow";

/** TTL of the allow records; only read locally by the secondaries' Lua (dblookup). */
const ALLOW_RECORD_TTL = 60;

export function isDnsEnabled(): boolean {
  return !!getPdnsApiUrl() && !!getDnsIpZone();
}

export function allowZoneName(): string {
  return `allow.${getDnsIpZone()}.invalid`;
}

/** Full 8×4 hex digits of an IPv6, lowercase, no separators; null if not plain IPv6. */
export function expandIPv6(ip: string): string | null {
  if (!isIPv6(ip) || ip.includes(".")) return null;
  const [head, tail] = ip.toLowerCase().split("::");
  const headGroups = head ? head.split(":") : [];
  const tailGroups = tail !== undefined && tail !== "" ? tail.split(":") : [];
  const fill = ip.includes("::") ? 8 - headGroups.length - tailGroups.length : 0;
  const groups = [...headGroups, ...Array(fill).fill("0"), ...tailGroups];
  return groups.map((g) => g.padStart(4, "0")).join("");
}

/** Allowlist record label for an IP, or null for an address the zone can't hold. */
export function allowKey(ip: string): string | null {
  if (isIPv4(ip)) return ip.replace(/\./g, "-");
  return expandIPv6(ip);
}

/** Public IPs of agent routes (ip and domain types both carry `ip`): what ip.<zone> may answer. */
export function agentPublicIps(routes: Route[]): string[] {
  const ips = routes
    .filter((r) => r.source === "agent")
    .map((r) => r.ip)
    .filter((ip) => allowKey(ip) !== null && !isLanOrReserved(ip));
  return [...new Set(ips)];
}

/**
 * Record a route registration. Refreshes each agent IP's last-seen time and, when an
 * IP is new to the allowlist, syncs the zone right away (seconds, not the next pass).
 */
export async function noteRoutes(routes: Route[]): Promise<void> {
  if (!isDnsEnabled()) return;
  const ips = agentPublicIps(routes);
  if (ips.length === 0) return;

  const now = Date.now();
  // ZADD replies with the number of members that were not there yet.
  const added = await getRedisClient().zadd(ALLOW_KEY, ...ips.flatMap((ip) => [now, ip]));
  if (added > 0) {
    await syncAllow();
  }
}

/** Allowed IPs with their last-seen time, oldest first. */
export async function listAllowed(): Promise<{ ip: string; lastSeen: number }[]> {
  const raw = await getRedisClient().zrange(ALLOW_KEY, 0, -1, "WITHSCORES");
  const out: { ip: string; lastSeen: number }[] = [];
  for (let i = 0; i < raw.length; i += 2) {
    out.push({ ip: raw[i], lastSeen: parseInt(raw[i + 1], 10) });
  }
  return out;
}

export interface AllowSyncResult {
  pruned: string[];
  added: string[];
  removed: string[];
  created: string[];
}

/** RRsets the allow zone should hold, keyed "name type". */
function desiredAllowRRsets(ips: string[]): Map<string, pdns.PdnsRRset> {
  const zone = allowZoneName();
  const out = new Map<string, pdns.PdnsRRset>();
  for (const ip of ips) {
    const key = allowKey(ip);
    if (!key) continue;
    const rrset: pdns.PdnsRRset = {
      name: pdns.fqdn(`${key}.${zone}`),
      type: isIPv4(ip) ? "A" : "AAAA",
      ttl: ALLOW_RECORD_TTL,
      records: [{ content: ip, disabled: false }],
    };
    out.set(`${rrset.name} ${rrset.type}`, rrset);
  }
  return out;
}

/** Create the catalog and the allow zone if the primary lacks them (disposable primary). */
async function ensureZones(created: string[]): Promise<pdns.PdnsZone> {
  const catalog = getDnsCatalogZone();
  if (!(await pdns.getZone(catalog))) {
    await pdns.createZone(catalog, "Producer");
    created.push(catalog);
  }
  const zone = allowZoneName();
  let current = await pdns.getZone(zone);
  if (!current) {
    await pdns.createZone(zone, "Primary", { catalog });
    created.push(zone);
    current = await pdns.getZone(zone);
    if (!current) throw new Error(`zone ${zone} missing right after creation`);
  }
  return current;
}

async function runSyncAllow(dryRun: boolean): Promise<AllowSyncResult> {
  const redis = getRedisClient();
  const cutoff = Date.now() - getDnsAllowGraceSeconds() * 1000;
  const pruned = await redis.zrangebyscore(ALLOW_KEY, 0, cutoff);
  if (!dryRun && pruned.length > 0) {
    await redis.zrem(ALLOW_KEY, ...pruned);
  }
  const allowed = (await redis.zrangebyscore(ALLOW_KEY, cutoff + 1, "+inf"))
    .filter((ip) => !pruned.includes(ip));

  const created: string[] = [];
  const zone = dryRun
    ? (await pdns.getZone(allowZoneName())) ?? { rrsets: [] as pdns.PdnsRRset[] }
    : await ensureZones(created);

  const desired = desiredAllowRRsets(allowed);
  const changes: pdns.PdnsRRset[] = [];
  const added: string[] = [];
  const removed: string[] = [];

  const present = new Map<string, pdns.PdnsRRset>();
  for (const rrset of zone.rrsets) {
    if (rrset.type === "A" || rrset.type === "AAAA") {
      present.set(`${rrset.name} ${rrset.type}`, rrset);
    }
  }
  for (const [k, want] of desired) {
    const have = present.get(k);
    const same = have && have.records.length === 1 && have.records[0].content === want.records[0].content;
    if (!same) {
      changes.push({ ...want, changetype: "REPLACE" });
      added.push(want.records[0].content);
    }
  }
  for (const [k, have] of present) {
    if (!desired.has(k)) {
      changes.push({ name: have.name, type: have.type, changetype: "DELETE", records: [] });
      removed.push(have.records[0]?.content ?? have.name);
    }
  }

  if (!dryRun && changes.length > 0) {
    await pdns.patchRRsets(allowZoneName(), changes);
    await pdns.notifyZone(allowZoneName());
  }
  if (!dryRun && (added.length > 0 || removed.length > 0)) {
    console.log(
      `[dns] allowlist ${allowZoneName()}: ${added.length ? `+${added.join(" +")}` : ""}` +
        `${added.length && removed.length ? " " : ""}${removed.length ? `-${removed.join(" -")}` : ""}`
    );
  }
  return { pruned, added, removed, created };
}

let allowQueue: Promise<unknown> = Promise.resolve();

/**
 * Bring the allow zone on the primary in line with the allowlist: drop IPs unseen for
 * the grace period, write the differing RRsets, then NOTIFY. Calls are serialized.
 * `dryRun` computes the diff without writing (Redis or primary).
 */
export function syncAllow(dryRun = false): Promise<AllowSyncResult> {
  const run = allowQueue.then(() => runSyncAllow(dryRun));
  allowQueue = run.catch(() => undefined);
  return run;
}

let fullPassTimer: NodeJS.Timeout | null = null;

/** Periodic full pass (grace expiry, drift, a rebuilt primary). No-op when disabled. */
export function startDnsReconciler(intervalMs = 60_000): void {
  if (!isDnsEnabled() || fullPassTimer) return;
  const pass = () =>
    syncAllow().catch((e) => console.error(`[dns] allowlist sync failed: ${e.message ?? e}`));
  pass();
  fullPassTimer = setInterval(pass, intervalMs);
  console.log(`[dns] reconciler on: ${allowZoneName()} every ${intervalMs / 1000}s, grace ${getDnsAllowGraceSeconds()}s`);
}

export function stopDnsReconciler(): void {
  if (fullPassTimer) {
    clearInterval(fullPassTimer);
    fullPassTimer = null;
  }
}
