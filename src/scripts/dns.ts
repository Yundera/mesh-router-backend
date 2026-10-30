/**
 * mesh-cli dns <subcommand>   (flags go after the positional arguments)
 *
 *   dns status <user> [--json] [--ns <ip,…>]   zone state, delegation check, probe, answer, SOA per NS
 *   dns force <user> [--host <h>] auto|gateway|direct [--yes]
 *   dns probe <user>                           probe the box now
 *   dns acme <user>                            live DNS-01 challenge values and the update counter
 *   dns sync [<user>] [--dry-run] [--prune]    reconcile now: one user's zone, or allowlist + live zones;
 *                                              --prune drops zones whose label no user holds
 *   dns allow [--json]                         ip.<zone> allowlist: IPs, last registration, expiry
 *   dns zone [--dry-run]                       sync the apex zone (DNS_STATIC_ZONE_FILE + backend records)
 *   dns zone diff [--ns <ip,…>]                compare it with what nameservers answer (default: the
 *                                              zone's current public NS, i.e. Cloudflare before the switch)
 *
 * Talks to Firestore, Redis and the PowerDNS hidden primary with the backend's own env
 * (REDIS_URL, PDNS_API_URL, PDNS_API_KEY, DNS_IP_ZONE, DNS_GATEWAY_IPS, DNS_NS_HOSTS).
 * Every box gets a dormant zone on its first registration; it turns live by itself once the
 * parent zone holds `<user>.<zone> NS <one of DNS_NS_HOSTS>` (a Cloudflare record before the
 * cutoff, our own apex zone after it). Nothing here switches a user on or off.
 */
import { promises as dnsp } from "dns";
import { getFirestore } from "firebase-admin/firestore";
import { ACME_TXT_LIFETIME_MS, acmeRateState, listAcmeTxt } from "../services/AcmeDns.js";
import { initializeFb } from "../firebase/firebaseIntegration.js";
import { NSL_ROUTER_COLLECTION, NSLRouterData } from "../DataBaseDTO/DataBaseNSLRouter.js";
import { getAllUserDomains, getDomain } from "../services/Domain.js";
import {
  allowZoneName,
  isApexZoneEnabled,
  isDnsEnabled,
  isInScope,
  isUserZonesEnabled,
  listAllowed,
  listUserZoneLabels,
  liveMisses,
  LIVE_DOWNGRADE_CHECKS,
  loadApexRRsets,
  lookupDelegation,
  delegatesToUs,
  dropUserZone,
  probeUser,
  refreshLive,
  ScopeUser,
  setForce,
  syncAllow,
  syncAllUsers,
  syncApex,
  syncUser,
  userZoneName,
  viewUser,
  writeDormant,
} from "../services/DnsZones.js";
import { getZone, PdnsRRset } from "../services/PowerDns.js";
import { getDnsAllowGraceSeconds, getDnsNsHosts, getDnsStaticZoneFile, getServerDomain } from "../configuration/config.js";
import { flagValue, hasFlag, MISSING, positionals, renderTable } from "../cli/format.js";

const USAGE = [
  "Usage: mesh-cli dns <subcommand>   (flags after the arguments)",
  "  status <user> [--json] [--ns <ip,…>]",
  "  force <user> [--host <name>] auto|gateway|direct [--yes]",
  "  probe <user>",
  "  acme <user>",
  "  sync [<user>] [--dry-run] [--prune]",
  "  allow [--json]",
  "  zone [--dry-run]",
  "  zone diff [--ns <ip,…>]",
].join("\n");

function requireUserZones(): void {
  if (!isUserZonesEnabled()) {
    throw new Error("user zones are not configured: PDNS_API_URL, DNS_GATEWAY_IPS and DNS_NS_HOSTS must be set");
  }
}

/** Look a user up by domain label (e.g. "wisera"). */
async function findUser(label: string | undefined): Promise<{ uid: string; data: NSLRouterData }> {
  if (!label) throw new Error(`a user (domain label) is required\n${USAGE}`);
  initializeFb();
  const found = await getDomain(label.toLowerCase());
  if (!found) throw new Error(`no user with domain '${label}'`);
  return { uid: found.uid, data: found.domain };
}

async function reload(uid: string): Promise<NSLRouterData> {
  const doc = await getFirestore().collection(NSL_ROUTER_COLLECTION).doc(uid).get();
  return doc.data() as NSLRouterData;
}

/** SOA serial of `zone` as `server` (an IP) answers it, or an error text. */
async function soaAt(server: string, zone: string): Promise<string> {
  try {
    const resolver = new dnsp.Resolver({ timeout: 3000, tries: 1 });
    resolver.setServers([server]);
    return String((await resolver.resolveSoa(zone)).serial);
  } catch (e) {
    return `(${(e as NodeJS.ErrnoException).code ?? (e as Error).message})`;
  }
}

async function status(label: string | undefined, argv: string[]): Promise<void> {
  requireUserZones();
  const { uid, data } = await findUser(label);
  const user: ScopeUser = { uid, label: data.domainName, dns: data.dns };
  const view = await viewUser(user);

  const [primary, seen, misses] = await Promise.all([getZone(view.zone), lookupDelegation(data.domainName), liveMisses(data.domainName)]);
  const live = isInScope(data);
  const delegation = seen === null ? "(no conclusive answer from the public resolvers)"
    : seen.length === 0 ? "none in the parent zone"
    : `${seen.join(", ")}${delegatesToUs(seen, getDnsNsHosts()) ? "" : "   (not ours)"}`;
  const servers: { name: string; ip: string }[] = [];
  for (const host of getDnsNsHosts()) {
    try {
      for (const ip of await dnsp.resolve4(host)) servers.push({ name: host, ip });
    } catch {
      servers.push({ name: host, ip: "" });
    }
  }
  for (const ip of (flagValue(argv, "ns") || "").split(",").filter(Boolean)) servers.push({ name: ip, ip });
  const serials = await Promise.all(servers.map(async (s) => ({ ...s, serial: s.ip ? await soaAt(s.ip, view.zone) : "(no address)" })));

  if (hasFlag(argv, "json")) {
    console.log(JSON.stringify({
      user: data.domainName, uid, live, zone: primary ? (live ? "live" : "dormant") : "missing",
      delegation: seen, liveMisses: misses, settings: data.dns ?? {},
      ...view, primarySerial: primary?.serial ?? null, nameservers: serials,
    }, null, 2));
    return;
  }

  const a = view.answer;
  console.log(`${view.zone}   (uid ${uid})\n`);
  console.log(`zone           ${!primary ? "missing (created on the box's next route registration)" : live ? "live" : "dormant (gateway answer, nobody asks it)"}`);
  console.log(`delegation     ${delegation}${live && misses ? `   ${misses}/${LIVE_DOWNGRADE_CHECKS} misses before dormant` : ""}`);
  if (!live) console.log(`               to go live, the parent zone needs: ${getDnsNsHosts().map((h) => `${view.zone}. NS ${h}.`).join("  ")} (one is enough)`);
  console.log(`force          ${data.dns?.force ?? "auto"}${Object.keys(data.dns?.hostForce ?? {}).length ? `   hosts: ${Object.entries(data.dns?.hostForce ?? {}).map(([h, f]) => `${h}=${f}`).join(" ")}` : ""}`);
  console.log(`public IP      ${view.publicIp ?? MISSING}`);
  const p = view.probe;
  console.log(`probe          ${p ? `${p.at}  ${p.via === "gateway" ? "via gateway  " : ""}cert ${p.cert}${p.notAfter ? `  notAfter ${p.notAfter}` : ""}${p.issuer ? `  issuer ${p.issuer}` : ""}` : `${MISSING} (none within the last hour)`}`);
  if (p) console.log(`               ${p.reason}`);
  if (view.acmeTxt.length) console.log(`acme TXT       ${view.acmeTxt.join(" ")}`);
  console.log(`CAA accounts   ${view.caaAccounts.length ? view.caaAccounts.join(" ") : `${MISSING} (any CA may issue)`}`);
  console.log(`answer         ${live ? "" : "once live: "}${a.kind} ${a.ips.join(",")}   (${a.reason})`);
  for (const [host, h] of Object.entries(a.hosts)) {
    console.log(`               ${host}.${view.zone}: ${h.kind} ${h.ips.join(",")}   (${h.reason})`);
  }
  console.log("");
  renderTable(
    ["server", "address", "SOA serial"],
    [["primary", "—", primary ? String(primary.serial) : "(no zone)"], ...serials.map((s) => [s.name, s.ip || MISSING, s.serial])]
  );
}

async function force(label: string | undefined, value: string | undefined, argv: string[]): Promise<void> {
  requireUserZones();
  const host = flagValue(argv, "host")?.toLowerCase();
  if (value !== "auto" && value !== "gateway" && value !== "direct") {
    throw new Error("usage: mesh-cli dns force <user> [--host <name>] auto|gateway|direct [--yes]");
  }
  if (host !== undefined && !/^[a-z0-9-]+$/.test(host)) throw new Error(`--host must be one label (got '${host}')`);
  if (value === "direct" && !hasFlag(argv, "yes")) {
    throw new Error("direct answers the box IP even when it cannot serve the names (no trusted certificate): " +
      "the site breaks for that user. Add --yes to confirm.");
  }
  const { uid } = await findUser(label);
  const { data, result } = await setForce(uid, value, host);
  console.log(`${userZoneName(data.domainName)}${host ? ` host ${host}` : ""}: force ${value}`);
  if (result && isInScope(data)) {
    console.log(`answer ${result.answer.kind} ${result.answer.ips.join(",")} (${result.answer.reason})`);
    result.changed.forEach((c) => console.log(`  ${c}`));
  } else {
    console.log("(dormant: setting stored, applies once the zone is live)");
  }
}

async function probe(label: string | undefined): Promise<void> {
  requireUserZones();
  const { uid, data } = await findUser(label);
  const state = await probeUser({ uid, label: data.domainName, dns: data.dns });
  console.log(JSON.stringify(state, null, 2));
}

async function acme(label: string | undefined): Promise<void> {
  const { uid, data } = await findUser(label);
  const values = await listAcmeTxt(data.domainName);
  const rate = await acmeRateState(uid);
  console.log(`_acme-challenge.${userZoneName(data.domainName)}   (updates ${rate.used}/${rate.limit} this hour` +
    `${rate.used ? `, window resets in ${Math.ceil(rate.resetsIn / 60)} min` : ""})\n`);
  renderTable(
    ["value", "set", "expires"],
    values.map((v) => [v.value, new Date(v.at).toISOString(), new Date(v.at + ACME_TXT_LIFETIME_MS).toISOString()])
  );
}

async function sync(target: string | undefined, argv: string[]): Promise<void> {
  const dryRun = hasFlag(argv, "dry-run");
  if (dryRun) console.log("(dry run: nothing written)");
  if (target) {
    requireUserZones();
    const { uid, data: found } = await findUser(target);
    let data = found;
    // the delegation checked now, not at the next registration (a change is stored)
    if (!dryRun && await refreshLive(uid, data, true)) data = await reload(uid);
    const r = isInScope(data)
      ? await syncUser({ uid, label: data.domainName, dns: data.dns }, dryRun)
      : await writeDormant(data.domainName, dryRun);
    console.log(`${r.zone}: ${isInScope(data) ? "live" : "dormant"}, ${r.created ? "created, " : ""}answer ${r.answer.kind} ${r.answer.ips.join(",")} (${r.answer.reason})`);
    console.log(`${r.zone}: ${r.created ? "created, " : ""}answer ${r.answer.kind} ${r.answer.ips.join(",")} (${r.answer.reason})`);
    (r.changed.length ? r.changed : ["no change"]).forEach((c) => console.log(`  ${c}`));
    return;
  }
  if (isDnsEnabled()) {
    const r = await syncAllow(dryRun);
    const line = (name: string, items: string[]) => console.log(`allowlist ${name.padEnd(8)} ${items.length ? items.join(" ") : MISSING}`);
    line("created", r.created);
    line("expired", r.pruned);
    line("added", r.added);
    line("removed", r.removed);
  }
  if (isUserZonesEnabled()) {
    if (dryRun) {
      console.log("user zones: a dry run covers one user at a time (dns sync <user> --dry-run)");
      if (hasFlag(argv, "prune")) await prune(true);
      return;
    }
    initializeFb();
    const r = await syncAllUsers({ refreshScope: true });
    console.log(`live zones: ${r.synced} synced, ${r.probed} probed` +
      `${r.dormant.length ? `, back to dormant ${r.dormant.join(" ")}` : ""}${r.failed.length ? `, FAILED ${r.failed.join(" ")}` : ""}`);
    if (hasFlag(argv, "prune")) await prune();
  }
  if (isApexZoneEnabled()) {
    const r = await syncApex();
    console.log(`apex zone ${r.zone}: ${r.changed.length ? `${r.changed.length} RRset(s) changed` : "no change"}` +
      `${r.skipped.length ? `, ${r.skipped.length} file record(s) left out (dns zone)` : ""}`);
  }
}

/**
 * Drop the user zones whose label no user holds any more (a release the backend missed).
 * Reads every user doc: the one place that does, so it runs only when asked.
 */
async function prune(dryRun = false): Promise<void> {
  initializeFb();
  const held = new Set((await getAllUserDomains()).map((u) => u.data.domainName?.toLowerCase()).filter(Boolean));
  const orphans = (await listUserZoneLabels()).filter((label) => !held.has(label));
  for (const label of orphans) if (!dryRun) await dropUserZone(label);
  console.log(`prune: ${orphans.length ? `${dryRun ? "would drop" : "dropped"} ${orphans.join(" ")}` : "no orphan zone"}`);
}

async function allow(argv: string[]): Promise<void> {
  if (!isDnsEnabled()) throw new Error("the allowlist is not configured: PDNS_API_URL and DNS_IP_ZONE must be set");
  const grace = getDnsAllowGraceSeconds() * 1000;
  const rows = await listAllowed();
  if (hasFlag(argv, "json")) {
    console.log(JSON.stringify({ zone: allowZoneName(), graceSeconds: grace / 1000, ips: rows }, null, 2));
    return;
  }
  console.log(`${allowZoneName()}   (grace ${grace / 3_600_000}h, ${rows.length} IPs)\n`);
  renderTable(
    ["ip", "last registered", "expires"],
    rows.map((r) => [r.ip, new Date(r.lastSeen).toISOString(), new Date(r.lastSeen + grace).toISOString()])
  );
}

function requireApexZone(): void {
  if (!isApexZoneEnabled()) {
    throw new Error("the apex zone is not configured: DNS_STATIC_ZONE_FILE, PDNS_API_URL, DNS_GATEWAY_IPS and DNS_NS_HOSTS must be set");
  }
}

async function zoneSync(argv: string[]): Promise<void> {
  requireApexZone();
  initializeFb();
  const dryRun = hasFlag(argv, "dry-run");
  if (dryRun) console.log("(dry run: nothing written)");
  const r = await syncApex(dryRun);
  console.log(`${r.zone}   (${getDnsStaticZoneFile()})${r.created ? "   zone created" : ""}`);
  (r.changed.length ? r.changed : ["no change"]).forEach((c) => console.log(`  ${c}`));
  if (r.skipped.length) {
    console.log("\nleft out of the zone file:");
    r.skipped.forEach((l) => console.log(`  ${l}`));
  }
}

/** The records `server` answers for name/type, in PowerDNS content form, or an error code. */
async function answersAt(server: string, name: string, type: string): Promise<string[] | string> {
  const resolver = new dnsp.Resolver({ timeout: 3000, tries: 2 });
  resolver.setServers([server]);
  const dot = (n: string) => `${n.replace(/\.$/, "")}.`.toLowerCase();
  try {
    switch (type) {
      case "A": return await resolver.resolve4(name);
      case "AAAA": return await resolver.resolve6(name);
      case "CNAME": return (await resolver.resolveCname(name)).map(dot);
      case "NS": return (await resolver.resolveNs(name)).map(dot);
      case "MX": return (await resolver.resolveMx(name)).map((m) => `${m.priority} ${dot(m.exchange)}`);
      case "SRV": return (await resolver.resolveSrv(name)).map((r) => `${r.priority} ${r.weight} ${r.port} ${dot(r.name)}`);
      case "TXT": return (await resolver.resolveTxt(name)).map((chunks) => chunks.map((c) => `"${c}"`).join(" "));
      case "CAA": return (await resolver.resolveCaa(name)).map((c) => {
        const [tag, value] = Object.entries(c).find(([k]) => k !== "critical") ?? ["?", ""];
        return `${c.critical} ${tag} "${value}"`;
      });
      default: return "(type not compared)";
    }
  } catch (e) {
    return `(${(e as NodeJS.ErrnoException).code ?? (e as Error).message})`;
  }
}

/** TXT compared on the text (a resolver joins or splits strings its own way), the rest case-insensitive. */
function normalized(type: string, values: string[]): string {
  const one = (v: string) => (type === "TXT" ? v.replace(/"\s+"/g, "").replace(/^"|"$/g, "") : v.toLowerCase());
  return values.map(one).sort().join(" | ");
}

async function zoneDiff(argv: string[]): Promise<void> {
  if (!getDnsStaticZoneFile()) throw new Error("DNS_STATIC_ZONE_FILE is not set");
  initializeFb();
  const zone = getServerDomain();
  const { rrsets, skipped } = await loadApexRRsets();

  let servers = (flagValue(argv, "ns") || "").split(",").filter(Boolean).map((ip) => ({ name: ip, ip }));
  if (!servers.length) {
    for (const host of await dnsp.resolveNs(zone)) {
      for (const ip of await dnsp.resolve4(host).catch(() => [] as string[])) servers.push({ name: host, ip });
    }
    servers = servers.slice(0, 1); // the zone's public servers all hold the same data
  }
  for (const server of servers) {
    console.log(`${zone}: zone file + backend vs ${server.name} (${server.ip})\n`);
    const rows: string[][] = [];
    let differ = 0;
    for (const want of rrsets as PdnsRRset[]) {
      const got = await answersAt(server.ip, want.name, want.type);
      const wanted = want.records.map((r) => r.content);
      const same = Array.isArray(got) && normalized(want.type, got) === normalized(want.type, wanted);
      if (!same) differ++;
      rows.push([same ? "=" : "≠", want.name, want.type, wanted.join(" | "), same ? "" : Array.isArray(got) ? got.join(" | ") || MISSING : got]);
    }
    renderTable(["", "name", "type", "ours", "theirs (when different)"], rows);
    console.log(`\n${rrsets.length - differ} same, ${differ} different. Proxied Cloudflare names answer Cloudflare's addresses;` +
      " a delegation answers as a referral, which shows as an error here.");
  }
  if (skipped.length) {
    console.log("\nleft out of the zone file:");
    skipped.forEach((l) => console.log(`  ${l}`));
  }
  console.log("\nA name only the other side has is not listed: compare with its export for those.");
}

async function zoneCommand(arg: string | undefined, argv: string[]): Promise<void> {
  if (arg === "diff") return zoneDiff(argv);
  if (arg === undefined) return zoneSync(argv);
  throw new Error("usage: mesh-cli dns zone [--dry-run] | dns zone diff [--ns <ip,…>]");
}

export async function main(argv: string[]): Promise<void> {
  const [sub, arg1, arg2] = positionals(argv);
  switch (sub) {
    case "status": return status(arg1, argv);
    case "force": return force(arg1, arg2, argv);
    case "probe": return probe(arg1);
    case "acme": return acme(arg1);
    case "sync": return sync(arg1, argv);
    case "allow": return allow(argv);
    case "zone": return zoneCommand(arg1, argv);
    default:
      console.log(USAGE);
      if (sub) throw new Error(`unknown dns subcommand '${sub}'`);
  }
}
