import { isIPv4, isIPv6 } from "net";
import { promises as dnsp } from "dns";
import { promises as fsp } from "fs";
import { getRedisClient } from "../redis/redisClient.js";
import { FieldValue, getFirestore } from "firebase-admin/firestore";
import {
  getDnsAllowGraceSeconds,
  getDnsCatalogZone,
  getDnsGatewayIps,
  getDnsIpZone,
  getDnsNsHosts,
  getDnsStaticZoneFile,
  getPdnsApiUrl,
  getServerDomain,
} from "../configuration/config.js";
import { DnsForce, NSL_ROUTER_COLLECTION, NSLRouterData, NSLRouterDns } from "../DataBaseDTO/DataBaseNSLRouter.js";
import { isLanOrReserved } from "./Probe.js";
import { Route, getRoutes } from "./Routes.js";
import { DnsProbeState, getProbeState, probeBox, probeDue, saveProbeState } from "./DnsProbe.js";
import { getAcmeTxt } from "./AcmeDns.js";
import { boxGatewayIps, healthyGatewayIps, startGatewayHealth, stopGatewayHealth } from "./GatewayHealth.js";
import * as pdns from "./PowerDns.js";
import { parseZoneFile, ZoneFileError, ZoneRecord } from "./ZoneFile.js";

/**
 * Backend side of the nameserver (mesh-router-nameserver docs/architecture.md §10):
 * the backend is the only writer of the PowerDNS hidden primary; the public
 * secondaries follow by NOTIFY + AXFR, catalog zone included.
 *
 * Two kinds of zones:
 * - the ip.<zone> allowlist. ip.<zone> itself is a local Lua zone on each secondary that
 *   answers an IP only if allow.<ip-zone>.invalid holds <key> A|AAAA <ip> — key = dashed
 *   IPv4 or 32-digit expanded IPv6. Kept equal to the public IPs agents registered
 *   within the grace period.
 * - per-user zones <label>.<SERVER_DOMAIN>, one per box that registered routes. Dormant
 *   (fixed gateway answer, written once) until the parent zone delegates the name to our
 *   nameservers; then live (`dns.live`): box IP or gateway per the answer rule, probes,
 *   DNS-01 TXT, CAA. Nothing is set by hand: the NS record in the parent decides.
 * - the apex zone <SERVER_DOMAIN> itself, when DNS_STATIC_ZONE_FILE is set: the static
 *   file plus what the backend derives (apex NS, the * wildcard to the gateways, the
 *   ip.<zone> and every user zone's NS).
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

/**
 * Create the catalog (producer) zone if the primary lacks it (disposable primary), and
 * move an older one to CATALOG_SOA_EDIT_API. A catalog already stuck on a YYYYMMDDnn
 * serial stays stuck until its serial is brought back to the epoch by hand (two steps,
 * RFC 1982): logged, not fixed here.
 */
async function ensureCatalog(created: string[]): Promise<string> {
  const catalog = getDnsCatalogZone();
  const current = await pdns.getZone(catalog);
  if (!current) {
    await pdns.createZone(catalog, "Producer");
    created.push(catalog);
  } else if (current.soa_edit_api !== pdns.CATALOG_SOA_EDIT_API) {
    await pdns.setSoaEditApi(catalog, pdns.CATALOG_SOA_EDIT_API);
    console.log(`[dns] ${pdns.fqdn(catalog)}: SOA-EDIT-API ${current.soa_edit_api} -> none`);
    if (current.serial > Math.floor(Date.now() / 1000) + 86400) {
      console.warn(`[dns] ${pdns.fqdn(catalog)}: serial ${current.serial} is above the epoch, new members will not reach the secondaries until it is brought back`);
    }
  }
  return catalog;
}

/** Create the catalog and the allow zone if the primary lacks them (disposable primary). */
async function ensureZones(created: string[]): Promise<pdns.PdnsZone> {
  const catalog = await ensureCatalog(created);
  const zone = allowZoneName();
  let current = await pdns.getZone(zone);
  if (!current) {
    await pdns.createZone(zone, "Primary", { catalog });
    created.push(zone);
    await liftNewZone(zone);
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

let writeQueue: Promise<unknown> = Promise.resolve();

/** Run `fn` after every earlier primary write: one writer at a time. */
function serialized<T>(fn: () => Promise<T>): Promise<T> {
  const run = writeQueue.then(fn);
  writeQueue = run.catch(() => undefined);
  return run;
}

/**
 * Bring the allow zone on the primary in line with the allowlist: drop IPs unseen for
 * the grace period, write the differing RRsets, then NOTIFY. Calls are serialized.
 * `dryRun` computes the diff without writing (Redis or primary).
 */
export function syncAllow(dryRun = false): Promise<AllowSyncResult> {
  return serialized(() => runSyncAllow(dryRun));
}

// ============================================================================
// Per-user zones: <label>.<SERVER_DOMAIN> (architecture §4.2, §10.2)
// ============================================================================

/** TTL of the answer records: short, so a flip direct ↔ gateway lands fast. */
const ANSWER_TTL = 30;
const NS_TTL = 3600;
/** acme-dns serves challenge TXT with TTL 60 (architecture §7.2). */
const ACME_TXT_TTL = 60;
/** A box's accounts change rarely (rebuild, email change). */
const CAA_TTL = 300;
/** Probe each user in scope at most this often from the full pass. */
const PROBE_INTERVAL_MS = 10 * 60 * 1000;
/** A registration triggers a probe when the last one is older than this. */
const PROBE_ON_REGISTRATION_MS = 60 * 1000;
/** Users in scope are re-read from Firestore this often (reads are counted). */
const SCOPE_REFRESH_MS = 10 * 60 * 1000;
const PROBE_CONCURRENCY = 4;

export function isUserZonesEnabled(): boolean {
  return !!getPdnsApiUrl() && getDnsGatewayIps().length > 0 && getDnsNsHosts().length > 0;
}

export function userZoneName(label: string): string {
  return `${label.toLowerCase()}.${getServerDomain().toLowerCase()}`;
}

export type AnswerKind = "direct" | "gateway";

export interface HostAnswer {
  kind: AnswerKind;
  ips: string[];
  reason: string;
}

export interface DnsAnswer extends HostAnswer {
  // host label → answer, only where it differs from the user's answer
  hosts: Record<string, HostAnswer>;
}

export interface AnswerInput {
  force?: DnsForce;
  hostForce?: Record<string, "gateway" | "direct">;
  // IPv4 of the user's fresh agent routes; null when offline or behind NAT
  publicIp: string | null;
  // last probe within its TTL, or null
  probe: DnsProbeState | null;
  gatewayIps: string[];
}

/**
 * The answer rule (architecture §4.2): the box IP only when it is proven able to serve
 * the names itself (public IP, browser-trusted cert, fresh probe of that same IP), or
 * when an admin forces it; the gateway otherwise. Pure.
 */
export function answer(input: AnswerInput): DnsAnswer {
  const gateway = (reason: string): HostAnswer => ({ kind: "gateway", ips: input.gatewayIps, reason });
  const direct = (ip: string, reason: string): HostAnswer => ({ kind: "direct", ips: [ip], reason });

  const decide = (force: DnsForce | undefined): HostAnswer => {
    if (force === "gateway") return gateway("forced to the gateway");
    if (force === "direct") {
      return input.publicIp
        ? direct(input.publicIp, "forced direct (admin)")
        : gateway("forced direct, but no public IP");
    }
    if (!input.publicIp) return gateway("no public IP (offline or behind NAT)");
    if (!input.probe) return gateway("not probed yet");
    if (input.probe.publicIp !== input.publicIp) return gateway(`last probe was for ${input.probe.publicIp ?? "no IP"}`);
    if (input.probe.cert !== "trusted") return gateway(input.probe.reason);
    return direct(input.publicIp, input.probe.reason);
  };

  const user = decide(input.force);
  const hosts: Record<string, HostAnswer> = {};
  for (const [host, force] of Object.entries(input.hostForce || {})) {
    const own = decide(force);
    if (own.ips.join(",") !== user.ips.join(",")) hosts[host.toLowerCase()] = own;
  }
  return { ...user, hosts };
}

export function acmeChallengeName(zone: string): string {
  return pdns.fqdn(`_acme-challenge.${zone}`);
}

/** Let's Encrypt account URIs (production and staging): the only issuer of a box's zone certificates. */
const ACME_ACCOUNT_URI = /^https:\/\/acme(-staging)?-v02\.api\.letsencrypt\.org\/acme\/acct\/\d{1,20}$/;
/** A box holds one account per email it ever used. */
export const MAX_CAA_ACCOUNTS = 4;

export function isAcmeAccountUri(uri: unknown): uri is string {
  return typeof uri === "string" && ACME_ACCOUNT_URI.test(uri);
}

/**
 * The zone's CAA records (phase-1.1-gateway-tls.md §7): Let's Encrypt only, and only for the
 * box's own ACME accounts, for names and wildcards alike. No account = none (any CA may issue).
 */
export function caaRecords(accounts: string[]): string[] {
  const sorted = [...accounts].sort();
  return ["issue", "issuewild"].flatMap((tag) => sorted.map((a) => `0 ${tag} "letsencrypt.org; accounturi=${a}"`));
}

/**
 * The A, NS, DNS-01 TXT and CAA RRsets a user zone should hold (SOA is PowerDNS's).
 * `acmeTxt` = the live challenge values; none = no TXT RRset. `caaAccounts` = the box's
 * ACME accounts; none = no CAA RRset.
 */
export function desiredUserRRsets(
  zone: string, ans: DnsAnswer, nsHosts: string[], acmeTxt: string[] = [], caaAccounts: string[] = []
): pdns.PdnsRRset[] {
  const a = (name: string, ips: string[]): pdns.PdnsRRset => ({
    name: pdns.fqdn(name), type: "A", ttl: ANSWER_TTL,
    records: [...ips].sort().map((content) => ({ content, disabled: false })),
  });
  return [
    { name: pdns.fqdn(zone), type: "NS", ttl: NS_TTL, records: nsHosts.map((h) => ({ content: pdns.fqdn(h), disabled: false })).sort((x, y) => x.content.localeCompare(y.content)) },
    a(zone, ans.ips),
    a(`*.${zone}`, ans.ips),
    ...Object.entries(ans.hosts).map(([host, h]) => a(`${host}.${zone}`, h.ips)),
    ...(acmeTxt.length ? [{
      name: acmeChallengeName(zone), type: "TXT", ttl: ACME_TXT_TTL,
      records: [...acmeTxt].sort().map((v) => ({ content: `"${v}"`, disabled: false })),
    }] : []),
    ...(caaAccounts.length ? [{
      name: pdns.fqdn(zone), type: "CAA", ttl: CAA_TTL,
      records: caaRecords(caaAccounts).map((content) => ({ content, disabled: false })),
    }] : []),
  ];
}

function sameRecords(x: pdns.PdnsRRset | undefined, y: pdns.PdnsRRset): boolean {
  if (!x) return false;
  // TXT and CAA content is case-sensitive; names in A/NS content are not
  const norm = (r: pdns.PdnsRRset) => r.records.map((rec) => (r.type === "TXT" || r.type === "CAA" ? rec.content : rec.content.toLowerCase())).sort().join(",");
  return x.ttl === y.ttl && norm(x) === norm(y);
}

export interface ScopeUser {
  uid: string;
  label: string;
  dns?: NSLRouterDns;
}

export interface UserView {
  zone: string;
  publicIp: string | null;
  probe: DnsProbeState | null;
  answer: DnsAnswer;
  // live DNS-01 challenge values
  acmeTxt: string[];
  // the box's ACME accounts, published as CAA
  caaAccounts: string[];
}

/**
 * First IPv4 of the user's fresh agent routes (the nameserver is IPv4 only, §10.6).
 * `routes` when the caller already holds them.
 */
async function currentPublicIp(uid: string, routes?: Route[] | null): Promise<string | null> {
  const fresh = routes !== undefined ? routes || [] : (await getRoutes(uid)) || [];
  return agentPublicIps(fresh).find((ip) => isIPv4(ip)) ?? null;
}

/** Tunnel addresses of the user's fresh tunnel routes: which gateways reach a NAT box. */
export function tunnelIps(routes: Route[]): string[] {
  return [...new Set(routes.filter((r) => r.source === "tunnel" && typeof r.tunnelIp === "string").map((r) => r.tunnelIp as string))];
}

/** What the user's names answer right now, from stored state (no probe, no write). */
export async function viewUser(user: ScopeUser, routes?: Route[] | null): Promise<UserView> {
  const [fresh, probe, acmeTxt] = await Promise.all([
    routes !== undefined ? Promise.resolve(routes || []) : getRoutes(user.uid).then((r) => r || []),
    getProbeState(user.uid), getAcmeTxt(user.label),
  ]);
  const publicIp = await currentPublicIp(user.uid, fresh);
  const ans = answer({
    force: user.dns?.force, hostForce: user.dns?.hostForce, publicIp, probe,
    gatewayIps: boxGatewayIps(publicIp, tunnelIps(fresh)),
  });
  return { zone: userZoneName(user.label), publicIp, probe, answer: ans, acmeTxt, caaAccounts: user.dns?.caaAccounts ?? [] };
}

/** Probe the user's box now and store the result (through the gateway when behind NAT). */
export async function probeUser(user: ScopeUser): Promise<DnsProbeState> {
  const routes = (await getRoutes(user.uid)) || [];
  const publicIp = await currentPublicIp(user.uid, routes);
  const state = await probeBox(userZoneName(user.label), publicIp, {
    gatewayIp: boxGatewayIps(publicIp, tunnelIps(routes))[0] ?? null,
  });
  await saveProbeState(user.uid, state);
  return state;
}

/**
 * Probe when the last one is older than `minAgeMs` or was for another IP than the box's
 * current one (a tunnel registration can probe before the agent's route is in).
 */
async function probeIfDue(user: ScopeUser, minAgeMs: number): Promise<boolean> {
  const [state, ip] = await Promise.all([getProbeState(user.uid), currentPublicIp(user.uid)]);
  if (!probeDue(state, minAgeMs) && state?.publicIp === ip) return false;
  await probeUser(user);
  return true;
}

export interface UserSyncResult {
  zone: string;
  created: boolean;
  changed: string[];
  answer: DnsAnswer;
}

/** A live user's zone: the answer rule, challenge TXT and CAA. */
async function runSyncUser(user: ScopeUser, dryRun: boolean): Promise<UserSyncResult> {
  const view = await viewUser(user);
  const desired = desiredUserRRsets(view.zone, view.answer, getDnsNsHosts(), view.acmeTxt, view.caaAccounts);
  const { created, changed } = await applyUserZone(view.zone, desired, dryRun);
  if (!dryRun && changed.length > 0) {
    // the shadow log: one line per answer change of the user's own name
    const apex = changed.find((c) => c.startsWith(`${pdns.fqdn(view.zone)} A `));
    if (apex) console.log(`[dns] ${user.label}: ${apex} ${view.answer.kind} (${view.answer.reason})`);
  }
  return { zone: view.zone, created, changed, answer: view.answer };
}

/** The answer of a dormant zone: the configured gateways, nothing per box. */
function dormantAnswer(): DnsAnswer {
  return { kind: "gateway", ips: getDnsGatewayIps(), reason: "dormant: not delegated to our nameservers", hosts: {} };
}

/**
 * A dormant zone (the parent does not delegate it to us): NS and the gateways, no probe,
 * no TXT, no CAA. Nobody asks it until the NS record appears, and then the gateway is a
 * working answer until the backend sees the delegation.
 */
async function runWriteDormant(label: string, dryRun: boolean): Promise<UserSyncResult> {
  const zone = userZoneName(label);
  const ans = dormantAnswer();
  const { created, changed } = await applyUserZone(zone, desiredUserRRsets(zone, ans, getDnsNsHosts()), dryRun);
  if (!dryRun && created) console.log(`[dns] ${label}: dormant zone ${zone} created`);
  if (!dryRun) await getRedisClient().setex(zoneMarkKey(label), ZONE_MARK_TTL_SECONDS, "1").catch(() => undefined);
  return { zone, created, changed, answer: ans };
}

/** Bring a user zone's managed RRsets in line with `desired`, creating the zone if missing. */
async function applyUserZone(
  zone: string, desired: pdns.PdnsRRset[], dryRun: boolean
): Promise<{ created: boolean; changed: string[] }> {
  let current = await pdns.getZone(zone);
  let created = false;
  if (!current && !dryRun) {
    const catalog = await ensureCatalog([]);
    await pdns.createZone(zone, "Primary", { catalog, nameservers: getDnsNsHosts() });
    created = true;
    await liftNewZone(zone);
    current = await pdns.getZone(zone);
  }
  // what we manage: A and NS, the challenge TXT and the apex CAA; anything else is left alone
  const present = new Map<string, pdns.PdnsRRset>();
  const challenge = acmeChallengeName(zone);
  const apex = pdns.fqdn(zone);
  for (const rrset of current?.rrsets || []) {
    if (rrset.type === "A" || rrset.type === "NS" || (rrset.type === "TXT" && rrset.name === challenge)
      || (rrset.type === "CAA" && rrset.name === apex)) {
      present.set(`${rrset.name} ${rrset.type}`, rrset);
    }
  }

  const changes: pdns.PdnsRRset[] = [];
  const changed: string[] = [];
  const wanted = new Set<string>();
  for (const want of desired) {
    const key = `${want.name} ${want.type}`;
    wanted.add(key);
    const have = present.get(key);
    if (!sameRecords(have, want)) {
      changes.push({ ...want, changetype: "REPLACE" });
      changed.push(`${want.name} ${want.type} ${have ? have.records.map((r) => r.content).join(",") : "—"} → ${want.records.map((r) => r.content).join(",")}`);
    }
  }
  for (const [key, have] of present) {
    if (!wanted.has(key)) {
      changes.push({ name: have.name, type: have.type, changetype: "DELETE", records: [] });
      changed.push(`${have.name} ${have.type} ${have.records.map((r) => r.content).join(",")} → —`);
    }
  }

  if (!dryRun && changes.length > 0) {
    await pdns.patchRRsets(zone, changes);
    await pdns.notifyZone(zone);
  }
  return { created, changed };
}

/** Bring one live user's zone on the primary in line with its answer. Serialized. */
export function syncUser(user: ScopeUser, dryRun = false): Promise<UserSyncResult> {
  return serialized(() => runSyncUser(user, dryRun));
}

/** Write (or create) the dormant zone of a user that is not live. Serialized. */
export function writeDormant(label: string, dryRun = false): Promise<UserSyncResult> {
  return serialized(() => runWriteDormant(label, dryRun));
}

/**
 * Redis marker: the user's zone exists on the primary (saves a primary GET per
 * registration). It expires, so a wiped primary gets its dormant zones back within a day.
 */
const ZONE_MARK_TTL_SECONDS = 24 * 60 * 60;

function zoneMarkKey(label: string): string {
  return `dns:zone:${label.toLowerCase()}`;
}

/**
 * Make sure the user has a zone: a dormant one when it has none. An existing zone is left
 * as it is (it may be live). Cheap on the hot path: one Redis GET once the marker is set.
 */
export async function ensureUserZone(label: string): Promise<boolean> {
  const redis = getRedisClient();
  if (await redis.get(zoneMarkKey(label))) return false;
  return serialized(async () => {
    if (await pdns.getZone(userZoneName(label))) {
      await redis.setex(zoneMarkKey(label), ZONE_MARK_TTL_SECONDS, "1");
      return false;
    }
    return (await runWriteDormant(label, false)).created;
  });
}

/** Delete a user's zone from the primary (the domain was released or renamed). */
export function dropUserZone(label: string): Promise<boolean> {
  return serialized(async () => {
    const zone = userZoneName(label);
    const redis = getRedisClient();
    await redis.del(zoneMarkKey(label), liveKey(label), liveMissKey(label)).catch(() => undefined);
    if (!(await pdns.getZone(zone))) return false;
    await pdns.deleteZone(zone);
    // the catalog loses the member: make the secondaries re-transfer it and drop the zone
    const catalog = getDnsCatalogZone();
    if (await pdns.getZone(catalog)) {
      await pdns.bumpSerial(catalog);
      await pdns.notifyZone(catalog);
    }
    console.log(`[dns] ${label}: zone ${zone} removed from the nameservers`);
    return true;
  });
}

// --- who is in scope -------------------------------------------------------

let scope: Map<string, ScopeUser> | null = null;
let scopeLoadedAt = 0;

/**
 * A user's DNS settings changed (mesh-cli runs in its own process, so the server's cached
 * scope would otherwise keep the old ones and its next pass undo the change): the time of
 * the last change, in Redis. A process whose mark is older reloads its scope.
 */
const SCOPE_CHANGED_KEY = "dns:scope:changed";
let seenScopeMark = 0;

async function markScopeChanged(): Promise<void> {
  seenScopeMark = Date.now(); // this process already holds the change (rememberUser)
  await getRedisClient().set(SCOPE_CHANGED_KEY, String(seenScopeMark))
    .catch((e) => console.error(`[dns] scope change mark: ${e.message ?? e}`));
}

async function scopeMark(): Promise<number> {
  try {
    return Number(await getRedisClient().get(SCOPE_CHANGED_KEY)) || 0;
  } catch {
    return 0;
  }
}

/** Live users: the only ones probed and synced by the full pass. One indexed query. */
async function loadScope(): Promise<Map<string, ScopeUser>> {
  const out = new Map<string, ScopeUser>();
  const snap = await getFirestore().collection(NSL_ROUTER_COLLECTION).where("dns.live", "==", true).get();
  for (const doc of snap.docs) {
    const data = doc.data() as NSLRouterData;
    if (data.domainName) out.set(doc.id, { uid: doc.id, label: data.domainName, dns: data.dns });
  }
  return out;
}

async function getScope(force = false): Promise<Map<string, ScopeUser>> {
  const mark = await scopeMark();
  if (force || !scope || Date.now() - scopeLoadedAt > SCOPE_REFRESH_MS || mark > seenScopeMark) {
    scope = await loadScope();
    scopeLoadedAt = Date.now();
    seenScopeMark = Math.max(seenScopeMark, mark);
  }
  return scope;
}

/** True when the user is live: the parent zone delegates its names to our nameservers. */
export function isInScope(data: NSLRouterData | null | undefined): boolean {
  return !!data?.domainName && !!data.dns?.live;
}

/** Update one user's entry in the cached scope (after a CLI change or a registration). */
function rememberUser(user: ScopeUser | null, uid: string): void {
  if (!scope) return;
  if (user) scope.set(uid, user);
  else scope.delete(uid);
}

/**
 * After a route registration (fire and forget): make sure the user has a zone (dormant
 * the first time), check the delegation when due, then probe and sync a live user.
 * `data` is the user doc the registration already read: no Firestore read here.
 */
export async function onRegistration(uid: string, data: NSLRouterData | null): Promise<void> {
  if (!isUserZonesEnabled() || !data?.domainName) return;
  await ensureUserZone(data.domainName);
  if (await refreshLive(uid, data)) return; // changed: refreshLive synced the zone
  if (!isInScope(data)) return;
  const user: ScopeUser = { uid, label: data.domainName, dns: data.dns };
  rememberUser(user, uid);
  await probeIfDue(user, PROBE_ON_REGISTRATION_MS);
  await syncUser(user);
}

// --- live = the parent zone really delegates the user's zone to us ---------

/** Public resolvers asked whether the delegation is in place. */
const LIVE_RESOLVERS = ["1.1.1.1", "8.8.8.8"];
/** Kept this long, re-checked every LIVE_REFRESH_SECONDS: a reader never meets a gap. */
const LIVE_TTL_SECONDS = 60 * 60;
const LIVE_REFRESH_SECONDS = 10 * 60;
/** A live user goes back to dormant only after this many "not delegated" answers in a row. */
export const LIVE_DOWNGRADE_CHECKS = 3;

function liveKey(label: string): string {
  return `dns:live:${label.toLowerCase()}`;
}

function liveMissKey(label: string): string {
  return `dns:livemiss:${label.toLowerCase()}`;
}

/** True when the NS set seen in the parent names at least one of our nameservers. Pure. */
export function delegatesToUs(nsSet: string[], nsHosts: string[]): boolean {
  const norm = (h: string) => h.toLowerCase().replace(/\.+$/, "");
  const ours = new Set(nsHosts.map(norm));
  return nsSet.some((h) => ours.has(norm(h)));
}

/**
 * What the public resolvers see as the NS set of <label>.<zone>: the names, [] when the
 * parent has no NS there, null when there is no conclusive answer (timeout, SERVFAIL…).
 */
export async function lookupDelegation(label: string): Promise<string[] | null> {
  try {
    const resolver = new dnsp.Resolver({ timeout: 3000, tries: 2 });
    resolver.setServers(LIVE_RESOLVERS);
    return await resolver.resolveNs(userZoneName(label));
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    return code === dnsp.NODATA || code === dnsp.NOTFOUND ? [] : null;
  }
}

/**
 * Live = a public resolver returns one of our DNS_NS_HOSTS in the NS set of <label>.<zone>:
 * the parent delegates it to us, so a CA validating DNS-01 (and every browser) reaches our
 * nameservers. `wasLive` = the stored state. No conclusive answer keeps it; a live user
 * turns dormant only after LIVE_DOWNGRADE_CHECKS misses in a row (a box flips its
 * certificates on this flag: mesh-router-caddy's zone file). `lookup` for the tests.
 */
export async function checkLive(
  label: string, wasLive: boolean, lookup: (label: string) => Promise<string[] | null> = lookupDelegation
): Promise<boolean> {
  const redis = getRedisClient();
  const seen = await lookup(label);
  let live: boolean;
  if (seen === null) {
    live = wasLive;
  } else if (delegatesToUs(seen, getDnsNsHosts())) {
    live = true;
    if (wasLive) await redis.del(liveMissKey(label));
  } else if (wasLive) {
    const misses = await redis.incr(liveMissKey(label));
    await redis.expire(liveMissKey(label), LIVE_TTL_SECONDS);
    live = misses < LIVE_DOWNGRADE_CHECKS;
    if (!live) await redis.del(liveMissKey(label));
  } else {
    live = false;
  }
  await redis.setex(liveKey(label), LIVE_TTL_SECONDS, live ? "1" : "0");
  return live;
}

/** True when the live flag is missing or older than LIVE_REFRESH_SECONDS. */
async function liveDue(label: string): Promise<boolean> {
  const ttl = await getRedisClient().ttl(liveKey(label));
  return ttl < 0 || ttl <= LIVE_TTL_SECONDS - LIVE_REFRESH_SECONDS;
}

/** Misses counted towards a downgrade (mesh-cli dns status). */
export async function liveMisses(label: string): Promise<number> {
  return Number(await getRedisClient().get(liveMissKey(label))) || 0;
}

/** Labels with a check in flight: a box registers its agent and tunnel routes together. */
const liveChecking = new Set<string>();

/**
 * Check the delegation when due (or now with `force`) and store a change: `dns.live` in
 * Firestore (written on transitions only), the scope, and the zone (live answer or
 * dormant). True when the state changed.
 */
export async function refreshLive(uid: string, data: NSLRouterData, force = false): Promise<boolean> {
  const label = data.domainName.toLowerCase();
  if (liveChecking.has(label) || (!force && !(await liveDue(label)))) return false;
  liveChecking.add(label);
  try {
    const wasLive = !!data.dns?.live;
    const live = await checkLive(label, wasLive);
    if (live === wasLive) return false;
    await setLive(uid, data, live);
    return true;
  } finally {
    liveChecking.delete(label);
  }
}

async function setLive(uid: string, data: NSLRouterData, live: boolean): Promise<void> {
  await getFirestore().collection(NSL_ROUTER_COLLECTION).doc(uid).update(
    live
      // `delegated` is the flag of the manual flow this replaces: dropped on the way
      ? { "dns.live": true, "dns.delegated": FieldValue.delete() }
      : { "dns.live": FieldValue.delete() }
  );
  console.log(`[dns] ${data.domainName}: ${live ? "live (delegated to our nameservers)" : "dormant (no delegation any more)"}`);
  const { live: _was, ...rest } = data.dns ?? {};
  await resyncUser(uid, { ...data, dns: live ? { ...rest, live: true } : rest });
}

/** Live users in the current scope. */
export async function liveUsers(): Promise<ScopeUser[]> {
  return [...(await getScope()).values()];
}

// --- the apex zone: <SERVER_DOMAIN> itself (architecture §9, §10.2) -----------
//
// The static zone file (DNS_STATIC_ZONE_FILE, server config bind-mounted next to the
// backend) holds what nobody derives: the apex address, mail, site verification, the
// nameservers' own addresses. The backend adds the rest and owns the whole zone: a
// record on the primary that is in neither is deleted. Until the registrar points the
// domain at our nameservers the zone is served but asked by nobody (`dig @ns`).

export function isApexZoneEnabled(): boolean {
  return !!getDnsStaticZoneFile() && isUserZonesEnabled();
}

export interface ApexInput {
  zone: string;
  records: ZoneRecord[];
  nsHosts: string[];
  gatewayIps: string[];
  /** DNS_IP_ZONE: delegated when it sits under the zone. */
  ipZone?: string;
  /** Labels of every user zone on the primary: <label>.<zone> NS our nameservers. */
  userZones: string[];
}

/**
 * The RRsets the apex zone should hold (SOA is PowerDNS's) and the static records left
 * out, with why: a name+type the backend owns, or a name at or below a delegation.
 * Throws a ZoneFileError when the file contradicts itself (CNAME beside other data).
 */
export function desiredApexRRsets(input: ApexInput): { rrsets: pdns.PdnsRRset[]; skipped: string[] } {
  const apex = pdns.fqdn(input.zone).toLowerCase();
  const nsRecords = [...input.nsHosts].map((h) => ({ content: pdns.fqdn(h), disabled: false }))
    .sort((x, y) => x.content.localeCompare(y.content));
  const ns = (name: string): pdns.PdnsRRset => ({ name, type: "NS", ttl: NS_TTL, records: nsRecords });

  const cuts: string[] = [];
  const dynamic: pdns.PdnsRRset[] = [ns(apex)];
  if (input.gatewayIps.length) {
    dynamic.push({
      name: `*.${apex}`, type: "A", ttl: ANSWER_TTL,
      records: [...input.gatewayIps].sort().map((content) => ({ content, disabled: false })),
    });
  }
  const ipZone = input.ipZone ? pdns.fqdn(input.ipZone).toLowerCase() : null;
  if (ipZone && ipZone.endsWith(`.${apex}`)) cuts.push(ipZone);
  for (const label of [...input.userZones].sort()) cuts.push(pdns.fqdn(userZoneName(label)).toLowerCase());
  dynamic.push(...cuts.map(ns));

  const owned = new Set(dynamic.map((r) => `${r.name} ${r.type}`));
  const groups = new Map<string, pdns.PdnsRRset>();
  const skipped: string[] = [];
  for (const rec of input.records) {
    const key = `${rec.name} ${rec.type}`;
    const cut = cuts.find((c) => rec.name === c || rec.name.endsWith(`.${c}`));
    if (owned.has(key)) {
      skipped.push(`line ${rec.line}: ${key} is set by the backend`);
      continue;
    }
    if (cut) {
      skipped.push(`line ${rec.line}: ${key} is at or below the delegation of ${cut}`);
      continue;
    }
    const group = groups.get(key) ?? { name: rec.name, type: rec.type, ttl: rec.ttl, records: [] };
    // one TTL per RRset: the lowest the file gives
    group.ttl = Math.min(group.ttl, rec.ttl);
    if (!group.records.some((r) => r.content === rec.content)) group.records.push({ content: rec.content, disabled: false });
    groups.set(key, group);
  }

  const rrsets = [...dynamic, ...groups.values()];
  const errors: string[] = [];
  for (const cname of rrsets.filter((r) => r.type === "CNAME")) {
    const others = rrsets.filter((r) => r.name === cname.name && r.type !== "CNAME");
    if (others.length) errors.push(`${cname.name} has a CNAME and ${others.map((r) => r.type).join(", ")}: a CNAME must be alone`);
    if (cname.records.length > 1) errors.push(`${cname.name} has ${cname.records.length} CNAME targets: one only`);
  }
  if (errors.length) throw new ZoneFileError(errors);
  return { rrsets, skipped };
}

export interface ApexSyncResult {
  zone: string;
  created: boolean;
  changed: string[];
  skipped: string[];
}

/** The zone file read now, plus the backend's records: what the apex zone should hold. */
export async function loadApexRRsets(): Promise<{ rrsets: pdns.PdnsRRset[]; skipped: string[] }> {
  const file = getDnsStaticZoneFile();
  if (!file) throw new Error("DNS_STATIC_ZONE_FILE is not set");
  const zone = getServerDomain();
  const records = parseZoneFile(await fsp.readFile(file, "utf8"), zone);
  return desiredApexRRsets({
    zone, records, nsHosts: getDnsNsHosts(), gatewayIps: healthyGatewayIps(), ipZone: getDnsIpZone(),
    userZones: await listUserZoneLabels(),
  });
}

async function runSyncApex(dryRun: boolean): Promise<ApexSyncResult> {
  const zone = getServerDomain();
  const { rrsets: desired, skipped } = await loadApexRRsets();

  let current = await pdns.getZone(zone);
  let created = false;
  if (!current && !dryRun) {
    const catalog = await ensureCatalog([]);
    await pdns.createZone(zone, "Primary", { catalog, nameservers: getDnsNsHosts() });
    created = true;
    await liftNewZone(zone);
    current = await pdns.getZone(zone);
  }
  // the whole zone is ours but the SOA
  const present = new Map<string, pdns.PdnsRRset>();
  for (const rrset of current?.rrsets || []) {
    if (rrset.type !== "SOA") present.set(`${rrset.name.toLowerCase()} ${rrset.type}`, rrset);
  }
  const changes: pdns.PdnsRRset[] = [];
  const changed: string[] = [];
  const wanted = new Set<string>();
  for (const want of desired) {
    const key = `${want.name} ${want.type}`;
    wanted.add(key);
    const have = present.get(key);
    if (!sameRecords(have, want)) {
      changes.push({ ...want, changetype: "REPLACE" });
      changed.push(`${key} ${have ? `${have.records.map((r) => r.content).join(",")} (${have.ttl})` : "—"} → ${want.records.map((r) => r.content).join(",")} (${want.ttl})`);
    }
  }
  for (const [key, have] of present) {
    if (!wanted.has(key)) {
      changes.push({ name: have.name, type: have.type, changetype: "DELETE", records: [] });
      changed.push(`${key} ${have.records.map((r) => r.content).join(",")} → —`);
    }
  }
  if (!dryRun && changes.length > 0) {
    await pdns.patchRRsets(zone, changes);
    await pdns.notifyZone(zone);
    console.log(`[dns] ${pdns.fqdn(zone)}: ${changed.length} RRset(s) changed${created ? " (zone created)" : ""}`);
    changed.forEach((c) => console.log(`[dns]   ${c}`));
  }
  return { zone, created, changed, skipped };
}

/**
 * Bring the apex zone on the primary in line with the zone file and the backend's
 * records. Serialized with the other writes. A file that does not parse changes nothing.
 */
export function syncApex(dryRun = false): Promise<ApexSyncResult> {
  return serialized(() => runSyncApex(dryRun));
}

/** Last apex problem logged, so a broken file is reported once, not every pass. */
let apexReported = "";

async function syncApexLogged(): Promise<void> {
  let report = "";
  try {
    const r = await syncApex();
    if (r.skipped.length) report = `[dns] ${pdns.fqdn(r.zone)}: zone file records left out:\n${r.skipped.map((l) => `[dns]   ${l}`).join("\n")}`;
  } catch (e) {
    report = `[dns] ${pdns.fqdn(getServerDomain())}: apex zone not synced: ${(e as Error).message ?? e}`;
  }
  if (report && report !== apexReported) console.error(report);
  if (!report && apexReported) console.log(`[dns] ${pdns.fqdn(getServerDomain())}: zone file OK again`);
  apexReported = report;
}

// --- serials: the primary must stay ahead of the secondaries -----------------
//
// A zone the primary recreates (wiped volume, zone dropped and re-added) starts at
// today's YYYYMMDD01, which can be BELOW what the secondaries still hold: they would
// then ignore every change until the primary caught up. So the backend compares each
// zone's serial with the nameservers' and lifts the primary above the highest.

const SERIAL_CHECK_MS = 10 * 60 * 1000;
let serialsCheckedAt = 0;

/** Highest SOA serial the DNS_NS_HOSTS serve for `zone`, or null when none answers. */
export async function nameserverSerial(zone: string, addresses?: string[]): Promise<number | null> {
  const ips = addresses ?? (await Promise.all(getDnsNsHosts().map((h) => dnsp.resolve4(h).catch(() => [] as string[])))).flat();
  let max: number | null = null;
  for (const ip of ips) {
    try {
      const resolver = new dnsp.Resolver({ timeout: 2000, tries: 1 });
      resolver.setServers([ip]);
      const serial = (await resolver.resolveSoa(zone)).serial;
      if (max === null || serial > max) max = serial;
    } catch {
      // that nameserver does not have the zone (yet) or is down
    }
  }
  return max;
}

/**
 * A zone the primary just created: start above whatever the nameservers still hold
 * (a recreated zone). Called inside the write queue, so not serialized again.
 */
async function liftNewZone(zone: string): Promise<void> {
  const theirs = await nameserverSerial(zone);
  if (theirs !== null && await pdns.setSerialAtLeast(zone, theirs + 1)) {
    console.log(`[dns] ${pdns.fqdn(zone)}: recreated, serial started above the nameservers' ${theirs}`);
  }
}

/**
 * Lift `zone`'s serial on the primary above a nameserver that is AHEAD of it, then
 * NOTIFY. Equal = in sync: nothing to do (lifting then would re-transfer every zone on
 * every check).
 */
export async function catchUpSerial(zone: string, addresses?: string[]): Promise<boolean> {
  const theirs = await nameserverSerial(zone, addresses);
  if (theirs === null) return false;
  const ours = (await pdns.getZone(zone))?.serial ?? 0;
  if (theirs <= ours) return false;
  const lifted = await serialized(() => pdns.setSerialAtLeast(zone, theirs + 1));
  if (lifted) {
    await pdns.notifyZone(zone);
    console.log(`[dns] ${pdns.fqdn(zone)}: serial lifted above the nameservers' ${theirs}`);
  }
  return lifted;
}

/**
 * Every zone on the primary but the dormant user zones, at most once per SERIAL_CHECK_MS
 * (or now with force). A dormant zone is written once, and liftNewZone already starts a
 * recreated one above the nameservers; it is checked again once live.
 */
export async function catchUpSerials(force = false): Promise<string[]> {
  if (!force && Date.now() - serialsCheckedAt < SERIAL_CHECK_MS) return [];
  serialsCheckedAt = Date.now();
  const lifted: string[] = [];
  const live = new Set(isUserZonesEnabled() ? (await liveUsers()).map((u) => u.label.toLowerCase()) : []);
  const suffix = `.${pdns.fqdn(getServerDomain())}`.toLowerCase();
  const catalog = pdns.fqdn(getDnsCatalogZone()).toLowerCase();
  for (const z of await pdns.listZones()) {
    if (z.kind === "Producer") continue; // the catalog's serial is PowerDNS's own
    const name = z.name.toLowerCase();
    const label = name.endsWith(suffix) ? name.slice(0, -suffix.length) : "";
    const userZone = /^[a-z0-9-]+$/.test(label) && z.catalog?.toLowerCase() === catalog;
    if (userZone && !live.has(label)) continue;
    try {
      if (await catchUpSerial(z.name)) lifted.push(z.name);
    } catch (e) {
      console.error(`[dns] ${z.name}: serial check failed: ${(e as Error).message ?? e}`);
    }
  }
  return lifted;
}

/** Run `fn` over `items`, at most `limit` at a time. */
async function pool<T>(items: T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  const queue = [...items];
  await Promise.all(Array.from({ length: Math.min(limit, queue.length) }, async () => {
    for (let item = queue.shift(); item !== undefined; item = queue.shift()) await fn(item);
  }));
}

export interface UsersPassResult {
  synced: number;
  probed: number;
  // live users whose delegation is gone: back to dormant
  dormant: string[];
  failed: string[];
}

/** The fields of a user doc that the live check and the zone writes read. */
function scopeData(user: ScopeUser): NSLRouterData {
  return { domainName: user.label, dns: user.dns } as NSLRouterData;
}

/**
 * Full pass over the live users: re-check the delegation when due (a user whose
 * delegation is gone turns dormant), probe when due, sync the zone. Dormant zones are not
 * touched: they change only on a registration, a release or a config change.
 */
export async function syncAllUsers(options: { refreshScope?: boolean } = {}): Promise<UsersPassResult> {
  const users = [...(await getScope(options.refreshScope)).values()];
  const result: UsersPassResult = { synced: 0, probed: 0, dormant: [], failed: [] };
  const left = new Set<string>();

  await pool(users, PROBE_CONCURRENCY, async (user) => {
    try {
      if (await refreshLive(user.uid, scopeData(user))) {
        left.add(user.uid);
        result.dormant.push(user.label);
        return;
      }
      if (await probeIfDue(user, PROBE_INTERVAL_MS)) result.probed++;
    } catch (e) {
      console.error(`[dns] ${user.label}: probe failed: ${(e as Error).message ?? e}`);
    }
  });
  for (const user of users) {
    if (left.has(user.uid)) continue;
    try {
      await syncUser(user);
      result.synced++;
    } catch (e) {
      result.failed.push(user.label);
      console.error(`[dns] ${user.label}: zone sync failed: ${(e as Error).message ?? e}`);
    }
  }
  return result;
}

/** Labels of our user zones on the primary: catalog members named <label>.<SERVER_DOMAIN>. */
export async function listUserZoneLabels(): Promise<string[]> {
  const suffix = `.${pdns.fqdn(getServerDomain())}`.toLowerCase();
  const catalog = pdns.fqdn(getDnsCatalogZone()).toLowerCase();
  const labels: string[] = [];
  for (const z of await pdns.listZones()) {
    const name = z.name.toLowerCase();
    const label = name.slice(0, -suffix.length);
    if (name.endsWith(suffix) && /^[a-z0-9-]+$/.test(label) && z.catalog?.toLowerCase() === catalog) labels.push(label);
  }
  return labels;
}

/** Redis: what the dormant zones were last written with (NS hosts + gateways). */
const DORMANT_CONFIG_KEY = "dns:dormant:config";

function dormantConfig(): string {
  return `ns=${[...getDnsNsHosts()].sort().join(",")} gw=${[...getDnsGatewayIps()].sort().join(",")}`;
}

/**
 * When DNS_NS_HOSTS or DNS_GATEWAY_IPS changed since the dormant zones were written,
 * rewrite every one of them once (live zones follow in the full pass). Returns how many
 * were rewritten.
 */
export async function refreshDormantZones(force = false): Promise<number> {
  const redis = getRedisClient();
  const config = dormantConfig();
  if (!force && (await redis.get(DORMANT_CONFIG_KEY)) === config) return 0;
  const live = new Set([...(await getScope(true)).values()].map((u) => u.label.toLowerCase()));
  let rewritten = 0;
  for (const label of await listUserZoneLabels()) {
    if (live.has(label)) continue;
    if ((await writeDormant(label)).changed.length) rewritten++;
  }
  await redis.set(DORMANT_CONFIG_KEY, config);
  if (rewritten) console.log(`[dns] ${rewritten} dormant zone(s) rewritten for ${config}`);
  return rewritten;
}

/**
 * Sync one user's zone after a change to its settings (CLI, owner API, live check): the
 * live answer when in scope, else the dormant zone.
 */
export async function resyncUser(uid: string, data: NSLRouterData | null): Promise<UserSyncResult | null> {
  if (data && isInScope(data)) {
    const user: ScopeUser = { uid, label: data.domainName, dns: data.dns };
    rememberUser(user, uid);
    await markScopeChanged();
    return syncUser(user);
  }
  rememberUser(null, uid);
  await markScopeChanged();
  return data?.domainName ? writeDormant(data.domainName) : null;
}

/**
 * Set a user's force (or one host's with `host`), then re-sync. "auto" removes the
 * override. Shared by `mesh-cli dns force` (any value) and the owner API (B7:
 * gateway|auto only, checked by the caller).
 */
export async function setForce(
  uid: string, value: DnsForce, host?: string
): Promise<{ data: NSLRouterData; result: UserSyncResult | null }> {
  if (host !== undefined && !/^[a-z0-9-]+$/.test(host)) throw new Error(`host must be one label (got '${host}')`);
  const ref = getFirestore().collection(NSL_ROUTER_COLLECTION).doc(uid);
  const field = host ? `dns.hostForce.${host}` : "dns.force";
  await ref.update({ [field]: value === "auto" ? FieldValue.delete() : value });
  let data = (await ref.get()).data() as NSLRouterData;
  // the last per-host override removed: drop the empty map too
  if (data.dns?.hostForce && Object.keys(data.dns.hostForce).length === 0) {
    await ref.update({ "dns.hostForce": FieldValue.delete() });
    data = (await ref.get()).data() as NSLRouterData;
  }
  // stored either way; written to a zone only where user zones run
  return { data, result: isUserZonesEnabled() ? await resyncUser(uid, data) : null };
}

/**
 * Store the box's ACME account URIs (deduplicated, sorted), then re-sync when they changed.
 * Same as an unchanged list: no write. Throws on an invalid list.
 */
export async function setCaaAccounts(
  uid: string, accounts: string[]
): Promise<{ changed: boolean; accounts: string[]; result: UserSyncResult | null }> {
  const list = [...new Set(accounts)].sort();
  if (list.length > MAX_CAA_ACCOUNTS || !list.every(isAcmeAccountUri)) {
    throw new Error(`accounts must be at most ${MAX_CAA_ACCOUNTS} Let's Encrypt account URIs`);
  }
  const ref = getFirestore().collection(NSL_ROUTER_COLLECTION).doc(uid);
  const before = ((await ref.get()).data() as NSLRouterData | undefined)?.dns?.caaAccounts ?? [];
  if (before.join(" ") === list.join(" ")) return { changed: false, accounts: list, result: null };
  await ref.update({ "dns.caaAccounts": list.length ? list : FieldValue.delete() });
  const data = (await ref.get()).data() as NSLRouterData;
  console.log(`[caa] ${data.domainName}: ${list.length ? list.join(" ") : "no account (CAA removed)"}`);
  // stored either way; written to a zone only where user zones run
  return { changed: true, accounts: list, result: isUserZonesEnabled() ? await resyncUser(uid, data) : null };
}

// ============================================================================

let fullPassTimer: NodeJS.Timeout | null = null;

/** Periodic full pass (grace expiry, drift, probes, a rebuilt primary). No-op when disabled. */
export function startDnsReconciler(intervalMs = 60_000): void {
  const allow = isDnsEnabled();
  const users = isUserZonesEnabled();
  if ((!allow && !users) || fullPassTimer) return;
  let running = false;
  let again = false; // a gateway changed during a pass: run once more right after
  let dormantChecked = false; // once per start: rewrite dormant zones if the config changed
  const pass = async (gatewayChange = false): Promise<void> => {
    if (running) {
      if (gatewayChange) again = true;
      return;
    }
    running = true;
    again = false;
    try {
      if (allow) {
        await syncAllow().catch((e) => console.error(`[dns] allowlist sync failed: ${e.message ?? e}`));
      }
      if (users) {
        if (!dormantChecked) {
          await refreshDormantZones().then(() => { dormantChecked = true; })
            .catch((e) => console.error(`[dns] dormant zones refresh failed: ${e.message ?? e}`));
        }
        await syncAllUsers().catch((e) => console.error(`[dns] user zones pass failed: ${e.message ?? e}`));
      }
      if (isApexZoneEnabled()) await syncApexLogged();
      await catchUpSerials().catch((e) => console.error(`[dns] serial check failed: ${e.message ?? e}`));
    } finally {
      running = false;
    }
    if (again) return pass();
  };
  pass();
  fullPassTimer = setInterval(() => void pass(), intervalMs);
  if (users) startGatewayHealth(() => void pass(true));
  if (allow) {
    console.log(`[dns] allowlist on: ${allowZoneName()} every ${intervalMs / 1000}s, grace ${getDnsAllowGraceSeconds()}s`);
  }
  if (users) {
    console.log(`[dns] user zones on (dormant per box, live once delegated): ` +
      `gateway ${getDnsGatewayIps().join(",")}, NS ${getDnsNsHosts().join(",")}`);
  }
  if (isApexZoneEnabled()) console.log(`[dns] apex zone on: ${getServerDomain()} from ${getDnsStaticZoneFile()}`);
}

export function stopDnsReconciler(): void {
  if (fullPassTimer) {
    clearInterval(fullPassTimer);
    fullPassTimer = null;
  }
  stopGatewayHealth();
}
