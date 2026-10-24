import { isIPv4, isIPv6 } from "net";
import { getRedisClient } from "../redis/redisClient.js";
import { FieldValue, getFirestore } from "firebase-admin/firestore";
import {
  getDnsAllowGraceSeconds,
  getDnsCatalogZone,
  getDnsGatewayIps,
  getDnsIpZone,
  getDnsNsHosts,
  getPdnsApiUrl,
  getServerDomain,
  isDnsShadowZones,
} from "../configuration/config.js";
import { DnsForce, NSL_ROUTER_COLLECTION, NSLRouterData, NSLRouterDns } from "../DataBaseDTO/DataBaseNSLRouter.js";
import { isLanOrReserved } from "./Probe.js";
import { Route, getRoutes, getActiveUserIds } from "./Routes.js";
import { getAllUserDomains } from "./Domain.js";
import { DnsProbeState, getProbeState, probeBox, probeDue, saveProbeState } from "./DnsProbe.js";
import { getAcmeTxt } from "./AcmeDns.js";
import * as pdns from "./PowerDns.js";

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
 * - per-user zones <label>.<SERVER_DOMAIN>: box IP or gateway per the answer rule, for
 *   delegated users (and every active user in shadow mode, DNS_SHADOW_ZONES=1).
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

/** Create the catalog (producer) zone if the primary lacks it (disposable primary). */
async function ensureCatalog(created: string[]): Promise<string> {
  const catalog = getDnsCatalogZone();
  if (!(await pdns.getZone(catalog))) {
    await pdns.createZone(catalog, "Producer");
    created.push(catalog);
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

/**
 * The A, NS and DNS-01 TXT RRsets a user zone should hold (SOA is PowerDNS's).
 * `acmeTxt` = the live challenge values; none = no TXT RRset.
 */
export function desiredUserRRsets(zone: string, ans: DnsAnswer, nsHosts: string[], acmeTxt: string[] = []): pdns.PdnsRRset[] {
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
  ];
}

function sameRecords(x: pdns.PdnsRRset | undefined, y: pdns.PdnsRRset): boolean {
  if (!x) return false;
  // TXT content is case-sensitive; names in A/NS content are not
  const norm = (r: pdns.PdnsRRset) => r.records.map((rec) => (r.type === "TXT" ? rec.content : rec.content.toLowerCase())).sort().join(",");
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
}

/**
 * First IPv4 of the user's fresh agent routes (the nameserver is IPv4 only, §10.6).
 * `routes` when the caller already holds them.
 */
async function currentPublicIp(uid: string, routes?: Route[] | null): Promise<string | null> {
  const fresh = routes !== undefined ? routes || [] : (await getRoutes(uid)) || [];
  return agentPublicIps(fresh).find((ip) => isIPv4(ip)) ?? null;
}

/** What the user's names answer right now, from stored state (no probe, no write). */
export async function viewUser(user: ScopeUser, routes?: Route[] | null): Promise<UserView> {
  const [publicIp, probe, acmeTxt] = await Promise.all([
    currentPublicIp(user.uid, routes), getProbeState(user.uid), getAcmeTxt(user.label),
  ]);
  const ans = answer({
    force: user.dns?.force, hostForce: user.dns?.hostForce, publicIp, probe, gatewayIps: getDnsGatewayIps(),
  });
  return { zone: userZoneName(user.label), publicIp, probe, answer: ans, acmeTxt };
}

/** Probe the user's box now and store the result. */
export async function probeUser(user: ScopeUser): Promise<DnsProbeState> {
  const state = await probeBox(userZoneName(user.label), await currentPublicIp(user.uid));
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

async function runSyncUser(user: ScopeUser, dryRun: boolean): Promise<UserSyncResult> {
  const view = await viewUser(user);
  const zone = view.zone;
  const desired = desiredUserRRsets(zone, view.answer, getDnsNsHosts(), view.acmeTxt);

  let current = await pdns.getZone(zone);
  let created = false;
  if (!current && !dryRun) {
    const catalog = await ensureCatalog([]);
    await pdns.createZone(zone, "Primary", { catalog, nameservers: getDnsNsHosts() });
    created = true;
    current = await pdns.getZone(zone);
  }
  // what we manage: A and NS, and the challenge TXT; anything else is left alone
  const present = new Map<string, pdns.PdnsRRset>();
  const challenge = acmeChallengeName(zone);
  for (const rrset of current?.rrsets || []) {
    if (rrset.type === "A" || rrset.type === "NS" || (rrset.type === "TXT" && rrset.name === challenge)) {
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
    // the shadow log: one line per answer change of the user's own name
    const apexKey = `${pdns.fqdn(zone)} A`;
    const before = present.get(apexKey)?.records.map((r) => r.content).sort().join(",") || "—";
    const after = view.answer.ips.join(",");
    if (before !== after) {
      console.log(`[dns] ${user.label}: ${before} → ${view.answer.kind} ${after} (${view.answer.reason})`);
    }
  }
  return { zone, created, changed, answer: view.answer };
}

/** Bring one user's zone on the primary in line with its answer. Serialized. */
export function syncUser(user: ScopeUser, dryRun = false): Promise<UserSyncResult> {
  return serialized(() => runSyncUser(user, dryRun));
}

/** Delete a user's zone from the primary (no longer in scope). */
export function dropUserZone(label: string): Promise<boolean> {
  return serialized(async () => {
    const zone = userZoneName(label);
    if (!(await pdns.getZone(zone))) return false;
    await pdns.deleteZone(zone);
    console.log(`[dns] ${label}: zone ${zone} removed from the nameservers`);
    return true;
  });
}

// --- who is in scope -------------------------------------------------------

let scope: Map<string, ScopeUser> | null = null;
let scopeLoadedAt = 0;

/** Delegated users, plus every active user (Redis activity) when shadow zones are on. */
async function loadScope(): Promise<Map<string, ScopeUser>> {
  const out = new Map<string, ScopeUser>();
  if (isDnsShadowZones()) {
    const active = new Set(await getActiveUserIds());
    for (const { userId, data } of await getAllUserDomains()) {
      if (data.dns?.delegated || active.has(userId)) {
        out.set(userId, { uid: userId, label: data.domainName, dns: data.dns });
      }
    }
  } else {
    const snap = await getFirestore().collection(NSL_ROUTER_COLLECTION).where("dns.delegated", "==", true).get();
    for (const doc of snap.docs) {
      const data = doc.data() as NSLRouterData;
      if (data.domainName) out.set(doc.id, { uid: doc.id, label: data.domainName, dns: data.dns });
    }
  }
  return out;
}

async function getScope(force = false): Promise<Map<string, ScopeUser>> {
  if (force || !scope || Date.now() - scopeLoadedAt > SCOPE_REFRESH_MS) {
    scope = await loadScope();
    scopeLoadedAt = Date.now();
  }
  return scope;
}

/** True when this user's names are served by our nameservers. */
export function isInScope(data: NSLRouterData | null | undefined): boolean {
  return !!data?.domainName && (!!data.dns?.delegated || isDnsShadowZones());
}

/** Update one user's entry in the cached scope (after a CLI change or a registration). */
function rememberUser(user: ScopeUser | null, uid: string): void {
  if (!scope) return;
  if (user) scope.set(uid, user);
  else scope.delete(uid);
}

/**
 * After a route registration (fire and forget): probe if due, then sync the user's
 * zone. `data` is the user doc the registration already read.
 */
export async function onRegistration(uid: string, data: NSLRouterData | null): Promise<void> {
  if (!isUserZonesEnabled() || !data || !isInScope(data)) return;
  const user: ScopeUser = { uid, label: data.domainName, dns: data.dns };
  rememberUser(user, uid);
  await probeIfDue(user, PROBE_ON_REGISTRATION_MS);
  await syncUser(user);
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
  removed: string[];
  failed: string[];
}

/**
 * Full pass over user zones: probe users whose probe is due, sync every zone in scope,
 * and delete our zones whose user left the scope (or changed domain).
 */
export async function syncAllUsers(options: { refreshScope?: boolean } = {}): Promise<UsersPassResult> {
  const users = [...(await getScope(options.refreshScope)).values()];
  const result: UsersPassResult = { synced: 0, probed: 0, removed: [], failed: [] };

  await pool(users, PROBE_CONCURRENCY, async (user) => {
    try {
      if (await probeIfDue(user, PROBE_INTERVAL_MS)) result.probed++;
    } catch (e) {
      console.error(`[dns] ${user.label}: probe failed: ${(e as Error).message ?? e}`);
    }
  });
  for (const user of users) {
    try {
      await syncUser(user);
      result.synced++;
    } catch (e) {
      result.failed.push(user.label);
      console.error(`[dns] ${user.label}: zone sync failed: ${(e as Error).message ?? e}`);
    }
  }

  // Our user zones = catalog members named <label>.<SERVER_DOMAIN>.
  const wanted = new Set(users.map((u) => pdns.fqdn(userZoneName(u.label))));
  const suffix = `.${pdns.fqdn(getServerDomain())}`;
  const catalog = pdns.fqdn(getDnsCatalogZone());
  for (const z of await pdns.listZones()) {
    const name = z.name.toLowerCase();
    const label = name.slice(0, -suffix.length);
    const ours = name.endsWith(suffix) && /^[a-z0-9-]+$/.test(label) && z.catalog?.toLowerCase() === catalog;
    if (ours && !wanted.has(name) && await dropUserZone(label)) result.removed.push(label);
  }
  return result;
}

/** Re-read one user from Firestore and sync (or drop) its zone: used after a CLI change. */
export async function resyncUser(uid: string, data: NSLRouterData | null): Promise<UserSyncResult | null> {
  if (data && isInScope(data)) {
    const user: ScopeUser = { uid, label: data.domainName, dns: data.dns };
    rememberUser(user, uid);
    return syncUser(user);
  }
  rememberUser(null, uid);
  if (data?.domainName) await dropUserZone(data.domainName);
  return null;
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
  const data = (await ref.get()).data() as NSLRouterData;
  // stored either way; written to a zone only where user zones run
  return { data, result: isUserZonesEnabled() ? await resyncUser(uid, data) : null };
}

// ============================================================================

let fullPassTimer: NodeJS.Timeout | null = null;

/** Periodic full pass (grace expiry, drift, probes, a rebuilt primary). No-op when disabled. */
export function startDnsReconciler(intervalMs = 60_000): void {
  const allow = isDnsEnabled();
  const users = isUserZonesEnabled();
  if ((!allow && !users) || fullPassTimer) return;
  let running = false;
  const pass = async () => {
    if (running) return;
    running = true;
    try {
      if (allow) {
        await syncAllow().catch((e) => console.error(`[dns] allowlist sync failed: ${e.message ?? e}`));
      }
      if (users) {
        await syncAllUsers().catch((e) => console.error(`[dns] user zones pass failed: ${e.message ?? e}`));
      }
    } finally {
      running = false;
    }
  };
  pass();
  fullPassTimer = setInterval(pass, intervalMs);
  if (allow) {
    console.log(`[dns] allowlist on: ${allowZoneName()} every ${intervalMs / 1000}s, grace ${getDnsAllowGraceSeconds()}s`);
  }
  if (users) {
    console.log(`[dns] user zones on (${isDnsShadowZones() ? "delegated + shadow for active users" : "delegated users"}): ` +
      `gateway ${getDnsGatewayIps().join(",")}, NS ${getDnsNsHosts().join(",")}`);
  }
}

export function stopDnsReconciler(): void {
  if (fullPassTimer) {
    clearInterval(fullPassTimer);
    fullPassTimer = null;
  }
}
