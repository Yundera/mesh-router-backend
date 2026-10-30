import { promises as dnsp } from "dns";
import { getDnsCatalogZone, getDnsIpZone, getDnsNsHosts, getServerDomain } from "../configuration/config.js";
import { isDnsEnabled, isUserZonesEnabled, liveUsers } from "./DnsZones.js";
import * as pdns from "./PowerDns.js";
import { GatewayState, gatewayStates } from "./GatewayHealth.js";

/**
 * Health of the public nameservers, for an external monitor (GET /dns/health).
 *
 * For each nameserver: it answers ip.<zone>, and holds every zone the secondaries copy
 * from the hidden primary (the catalog and its members) at the primary's serial. A zone
 * off that serial is
 *   pending   within LAG_GRACE_MS of the primary's last change to it (PowerDns.ts
 *             records each write): a transfer on its way, not a problem;
 *   missing   past it, and the nameserver does not serve the zone at all;
 *   behind    past it, at another serial.
 * The grace runs from the change, not from when a check first saw the difference, so a
 * zone that never arrived is reported on the first check, whatever the polling and
 * however recently the backend restarted.
 *
 *   ok        everything in sync             → 200
 *   degraded  a nameserver down or behind,   → 500
 *             the primary unreachable, or a gateway down (GatewayHealth.ts)
 *   down      no nameserver answers ip.<zone> → 503
 *   off       no nameserver configured       → 200
 *
 * Dormant user zones (one per box, asked by nobody) are counted, not sampled: the check
 * stays the same size whatever the fleet. Public: user zones are counted, never named
 * (the list of live users is not published here). Computed at most every CACHE_MS, so
 * the route costs no DNS traffic beyond that whatever the request rate.
 */

export type DnsHealthStatus = "ok" | "degraded" | "down" | "off";

export interface NameserverHealth {
  host: string;
  ip: string | null;
  answers: boolean;
  /** Past the grace, not served at all: names for system zones, a count for user zones. */
  missing: string[];
  missingUserZones: number;
  /** Past the grace, at another serial than the primary's. */
  behind: string[];
  behindUserZones: number;
  /** Off the primary's serial within the grace after a change (not a problem). */
  pending: number;
}

export interface DnsHealth {
  status: DnsHealthStatus;
  checkedAt: string;
  primary: { reachable: boolean; zones: number; dormantUserZones?: number };
  nameservers: NameserverHealth[];
  gateways: { ip: string; up: boolean; lastError?: string; changedAt?: string; tunnel?: { up: boolean; lastError?: string; changedAt?: string } }[];
  problems: string[];
}

const LAG_GRACE_MS = 5 * 60 * 1000;
const CACHE_MS = 60 * 1000;
const QUERY_TIMEOUT_MS = 2000;

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
  /** When the primary last changed the zone (ms), null = not recently */
  changedAt: number | null;
}

export interface ServerSample {
  host: string;
  ip: string | null;
  answers: boolean;
  zones: ZoneSample[];
}

/** The verdict from one round of samples. Pure. */
export function evaluate(
  servers: ServerSample[],
  primaryReachable: boolean,
  primaryZones: number,
  now: number,
  gateways: GatewayState[] = [],
): DnsHealth {
  const problems: string[] = [];
  const nameservers = servers.map((s): NameserverHealth => {
    const out: NameserverHealth = {
      host: s.host, ip: s.ip, answers: s.answers,
      missing: [], missingUserZones: 0, behind: [], behindUserZones: 0, pending: 0,
    };
    if (!s.ip) {
      problems.push(`${s.host}: no address`);
      return out;
    }
    if (!s.answers) {
      problems.push(`${s.host} (${s.ip}): no answer for ip.<zone>`);
      return out;
    }
    for (const z of s.zones) {
      if (z.theirs === z.primary) continue;
      if (z.changedAt !== null && now - z.changedAt < LAG_GRACE_MS) {
        out.pending++;
      } else if (z.theirs === null) {
        if (z.user) out.missingUserZones++;
        else out.missing.push(z.zone);
      } else {
        if (z.user) out.behindUserZones++;
        else out.behind.push(z.zone);
      }
    }
    if (out.missing.length) problems.push(`${s.host}: does not serve ${out.missing.join(", ")}`);
    if (out.missingUserZones) problems.push(`${s.host}: does not serve ${out.missingUserZones} user zone(s)`);
    if (out.behind.length) problems.push(`${s.host}: behind the primary on ${out.behind.join(", ")}`);
    if (out.behindUserZones) problems.push(`${s.host}: behind the primary on ${out.behindUserZones} user zone(s)`);
    return out;
  });
  if (!primaryReachable) problems.push("hidden primary unreachable: serials not compared");
  for (const g of gateways) {
    if (!g.up) problems.push(`gateway ${g.ip} down since ${g.changedAt ?? "?"}: ${g.lastError ?? "?"} (out of the answers)`);
    if (g.tunnel && !g.tunnel.up) {
      problems.push(`tunnel provider of gateway ${g.ip} down since ${g.tunnel.changedAt ?? "?"}: ${g.tunnel.lastError ?? "?"} (out of NAT boxes' answers)`);
    }
  }

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
    gateways: gateways.map(({ ip, up, lastError, changedAt, tunnel }) => ({
      ip, up, lastError, changedAt,
      ...(tunnel ? { tunnel: { up: tunnel.up, lastError: tunnel.lastError, changedAt: tunnel.changedAt } } : {}),
    })),
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
  let dormant = 0;
  if (primaryConfigured) {
    try {
      const members = (await pdns.listZones())
        .filter((z) => z.name.toLowerCase() === catalog || z.catalog?.toLowerCase() === catalog)
        .map((z) => ({
          zone: z.name.toLowerCase(),
          user: z.name.toLowerCase() !== catalog && !z.name.toLowerCase().endsWith(".invalid."),
          serial: z.serial,
        }));
      const live = new Set(isUserZonesEnabled() ? (await liveUsers()).map((u) => u.label.toLowerCase()) : []);
      const suffix = `.${pdns.fqdn(getServerDomain())}`.toLowerCase();
      const isDormant = (zone: string) => zone.endsWith(suffix) && /^[a-z0-9-]+$/.test(zone.slice(0, -suffix.length))
        && !live.has(zone.slice(0, -suffix.length));
      expected = members.filter((z) => !(z.user && isDormant(z.zone)));
      dormant = members.length - expected.length;
      primaryReachable = true;
    } catch (e) {
      console.error(`[dns-health] primary: ${(e as Error).message ?? e}`);
    }
  }
  let changedAt: (number | null)[] = expected.map(() => null);
  try {
    changedAt = await pdns.zonesChangedAt(expected.map((z) => z.zone));
  } catch (e) {
    // no grace then: a zone off the primary's serial is reported at once
    console.error(`[dns-health] change times: ${(e as Error).message ?? e}`);
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
        ? await Promise.all(expected.map(async (z, i) => ({
          zone: z.zone, user: z.user, primary: z.serial, theirs: await soaSerial(ip, z.zone), changedAt: changedAt[i],
        })))
        : [];
      servers.push({ host, ip, answers, zones });
    }
  }
  const health = evaluate(servers, primaryReachable || !primaryConfigured, expected.length, Date.now(), gatewayStates());
  if (dormant) health.primary.dormantUserZones = dormant;
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
