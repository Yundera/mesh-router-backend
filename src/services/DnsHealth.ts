import { promises as dnsp } from "dns";
import { getDnsCatalogZone, getDnsIpZone, getDnsNsHosts } from "../configuration/config.js";
import { isDnsEnabled, isUserZonesEnabled } from "./DnsZones.js";
import * as pdns from "./PowerDns.js";

/**
 * Health of the public nameservers, for an external monitor (GET /dns/health).
 *
 * For each nameserver: it answers ip.<zone>, and holds every zone the secondaries copy
 * from the hidden primary (the catalog and its members) at the primary's serial. A
 * zone may lag for LAG_GRACE_MS (a transfer in progress, a zone just created); past
 * that it is a problem. Lag is measured between checks, so it needs the monitor's
 * polling (every few minutes) to be reported.
 *
 *   ok        everything in sync             → 200
 *   degraded  a nameserver down or behind,   → 500
 *             or the primary unreachable
 *   down      no nameserver answers ip.<zone> → 503
 *   off       no nameserver configured       → 200
 *
 * Public: user zones are counted, never named (the list of delegated users is not
 * published here). Computed at most every CACHE_MS, so the route costs no DNS traffic
 * beyond that whatever the request rate.
 */

export type DnsHealthStatus = "ok" | "degraded" | "down" | "off";

export interface NameserverHealth {
  host: string;
  ip: string | null;
  answers: boolean;
  /** Zones not at the primary's serial past the grace: names for system zones, a count for user zones. */
  behind: string[];
  behindUserZones: number;
}

export interface DnsHealth {
  status: DnsHealthStatus;
  checkedAt: string;
  primary: { reachable: boolean; zones: number };
  nameservers: NameserverHealth[];
  problems: string[];
}

const LAG_GRACE_MS = 5 * 60 * 1000;
const CACHE_MS = 60 * 1000;
const QUERY_TIMEOUT_MS = 2000;

/** `<ip>|<zone>` → first check that saw this nameserver off the primary's serial (ms). */
const lagSince = new Map<string, number>();
let cached: { at: number; health: DnsHealth } | null = null;
let running: Promise<DnsHealth> | null = null;

export function httpStatusFor(status: DnsHealthStatus): number {
  return status === "down" ? 503 : status === "degraded" ? 500 : 200;
}

async function soaSerial(ip: string, zone: string): Promise<number | null> {
  try {
    const resolver = new dnsp.Resolver({ timeout: QUERY_TIMEOUT_MS, tries: 1 });
    resolver.setServers([ip]);
    return (await resolver.resolveSoa(zone)).serial;
  } catch {
    return null;
  }
}

/** DNS_NS_HOSTS, or else the NS of ip.<zone> as published. */
async function nameserverHosts(): Promise<string[]> {
  const hosts = getDnsNsHosts();
  if (hosts.length > 0) return hosts;
  const ipZone = getDnsIpZone();
  if (!ipZone) return [];
  try {
    return (await dnsp.resolveNs(ipZone)).map((h) => h.replace(/\.+$/, "").toLowerCase());
  } catch {
    return [];
  }
}

export interface ZoneSample {
  zone: string;
  user: boolean;
  primary: number;
  /** null = the nameserver does not answer for the zone */
  theirs: number | null;
}

export interface ServerSample {
  host: string;
  ip: string | null;
  answers: boolean;
  zones: ZoneSample[];
}

/**
 * The verdict from one round of samples. Pure but for `lag`, the first-seen-behind
 * times it reads and updates (entries of zones back in sync are dropped).
 */
export function evaluate(
  servers: ServerSample[],
  primaryReachable: boolean,
  primaryZones: number,
  now: number,
  lag: Map<string, number> = lagSince,
): DnsHealth {
  const problems: string[] = [];
  const seen = new Set<string>();
  const nameservers = servers.map((s): NameserverHealth => {
    const out: NameserverHealth = { host: s.host, ip: s.ip, answers: s.answers, behind: [], behindUserZones: 0 };
    if (!s.ip) {
      problems.push(`${s.host}: no address`);
      return out;
    }
    if (!s.answers) {
      problems.push(`${s.host} (${s.ip}): no answer for ip.<zone>`);
      return out;
    }
    for (const z of s.zones) {
      const key = `${s.ip}|${z.zone}`;
      if (z.theirs === z.primary) continue;
      seen.add(key);
      const since = lag.get(key) ?? now;
      lag.set(key, since);
      if (now - since < LAG_GRACE_MS) continue;
      if (z.user) out.behindUserZones++;
      else out.behind.push(z.zone);
    }
    if (out.behind.length) problems.push(`${s.host}: behind the primary on ${out.behind.join(", ")}`);
    if (out.behindUserZones) problems.push(`${s.host}: behind the primary on ${out.behindUserZones} user zone(s)`);
    return out;
  });
  for (const key of [...lag.keys()]) if (!seen.has(key)) lag.delete(key);
  if (!primaryReachable) problems.push("hidden primary unreachable: serials not compared");

  let status: DnsHealthStatus;
  if (servers.length === 0) status = "off";
  else if (!servers.some((s) => s.ip && s.answers)) status = "down";
  else status = problems.length ? "degraded" : "ok";
  if (servers.length === 0 && (isDnsEnabled() || isUserZonesEnabled())) {
    problems.push("no nameserver known (DNS_NS_HOSTS unset, no NS for ip.<zone>)");
    status = "degraded";
  }
  return {
    status,
    checkedAt: new Date(now).toISOString(),
    primary: { reachable: primaryReachable, zones: primaryZones },
    nameservers,
    problems,
  };
}

async function check(): Promise<DnsHealth> {
  const ipZone = getDnsIpZone();
  const catalog = pdns.fqdn(getDnsCatalogZone());

  // The zones the secondaries copy: the catalog and its members.
  const primaryConfigured = isDnsEnabled() || isUserZonesEnabled();
  let primaryReachable = false;
  let expected: { zone: string; user: boolean; serial: number }[] = [];
  if (primaryConfigured) {
    try {
      expected = (await pdns.listZones())
        .filter((z) => z.name.toLowerCase() === catalog || z.catalog?.toLowerCase() === catalog)
        .map((z) => ({
          zone: z.name.toLowerCase(),
          user: z.name.toLowerCase() !== catalog && !z.name.toLowerCase().endsWith(".invalid."),
          serial: z.serial,
        }));
      primaryReachable = true;
    } catch (e) {
      console.error(`[dns-health] primary: ${(e as Error).message ?? e}`);
    }
  }

  const servers: ServerSample[] = [];
  for (const host of await nameserverHosts()) {
    let ips: string[] = [];
    try {
      ips = await dnsp.resolve4(host);
    } catch {
      // reported as "no address"
    }
    if (ips.length === 0) servers.push({ host, ip: null, answers: false, zones: [] });
    for (const ip of ips) {
      const answers = ipZone ? (await soaSerial(ip, ipZone)) !== null : true;
      const zones = answers
        ? await Promise.all(expected.map(async (z) => ({ zone: z.zone, user: z.user, primary: z.serial, theirs: await soaSerial(ip, z.zone) })))
        : [];
      servers.push({ host, ip, answers, zones });
    }
  }
  const health = evaluate(servers, primaryReachable || !primaryConfigured, expected.length, Date.now());
  if (health.problems.length) console.warn(`[dns-health] ${health.status}: ${health.problems.join("; ")}`);
  return health;
}

/** The current health, recomputed at most every CACHE_MS (concurrent callers share a run). */
export async function getDnsHealth(): Promise<DnsHealth> {
  if (cached && Date.now() - cached.at < CACHE_MS) return cached.health;
  if (!running) {
    running = check()
      .then((health) => {
        cached = { at: Date.now(), health };
        return health;
      })
      .finally(() => {
        running = null;
      });
  }
  return running;
}
