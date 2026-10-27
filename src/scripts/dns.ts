/**
 * mesh-cli dns <subcommand>   (flags go after the positional arguments)
 *
 *   dns status <user> [--json] [--ns <ip,…>]   settings, probe, answer, SOA serial per NS
 *   dns delegate <user> on|off                 mark <user>.<zone> delegated to our nameservers
 *   dns force <user> [--host <h>] auto|gateway|direct [--yes]
 *   dns probe <user>                           probe the box now
 *   dns acme <user>                            live DNS-01 challenge values and the update counter
 *   dns sync [<user>] [--dry-run]              reconcile now: one user's zone, or allowlist + every zone
 *   dns allow [--json]                         ip.<zone> allowlist: IPs, last registration, expiry
 *
 * Talks to Firestore, Redis and the PowerDNS hidden primary with the backend's own env
 * (REDIS_URL, PDNS_API_URL, PDNS_API_KEY, DNS_IP_ZONE, DNS_GATEWAY_IPS, DNS_NS_HOSTS).
 * Delegation itself is an NS record added by hand where the parent zone lives.
 */
import { promises as dnsp } from "dns";
import { FieldValue, getFirestore } from "firebase-admin/firestore";
import { ACME_TXT_LIFETIME_MS, acmeRateState, listAcmeTxt } from "../services/AcmeDns.js";
import { initializeFb } from "../firebase/firebaseIntegration.js";
import { NSL_ROUTER_COLLECTION, NSLRouterData } from "../DataBaseDTO/DataBaseNSLRouter.js";
import { getDomain } from "../services/Domain.js";
import {
  allowZoneName,
  isDnsEnabled,
  isInScope,
  isUserZonesEnabled,
  listAllowed,
  probeUser,
  resyncUser,
  ScopeUser,
  setForce,
  syncAllow,
  syncAllUsers,
  syncUser,
  userZoneName,
  viewUser,
} from "../services/DnsZones.js";
import { getZone } from "../services/PowerDns.js";
import { getDnsAllowGraceSeconds, getDnsNsHosts, isDnsShadowZones } from "../configuration/config.js";
import { flagValue, hasFlag, MISSING, positionals, renderTable } from "../cli/format.js";

const USAGE = [
  "Usage: mesh-cli dns <subcommand>   (flags after the arguments)",
  "  status <user> [--json] [--ns <ip,…>]",
  "  delegate <user> on|off",
  "  force <user> [--host <name>] auto|gateway|direct [--yes]",
  "  probe <user>",
  "  acme <user>",
  "  sync [<user>] [--dry-run]",
  "  allow [--json]",
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

  const primary = await getZone(view.zone);
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
      user: data.domainName, uid, inScope: isInScope(data), settings: data.dns ?? {},
      ...view, primarySerial: primary?.serial ?? null, nameservers: serials,
    }, null, 2));
    return;
  }

  const a = view.answer;
  console.log(`${view.zone}   (uid ${uid})\n`);
  console.log(`served by us   ${isInScope(data) ? (data.dns?.delegated ? "yes (delegated)" : "yes (shadow zone, not delegated)") : "no"}`);
  console.log(`force          ${data.dns?.force ?? "auto"}${Object.keys(data.dns?.hostForce ?? {}).length ? `   hosts: ${Object.entries(data.dns?.hostForce ?? {}).map(([h, f]) => `${h}=${f}`).join(" ")}` : ""}`);
  console.log(`public IP      ${view.publicIp ?? MISSING}`);
  const p = view.probe;
  console.log(`probe          ${p ? `${p.at}  cert ${p.cert}${p.notAfter ? `  notAfter ${p.notAfter}` : ""}${p.issuer ? `  issuer ${p.issuer}` : ""}` : `${MISSING} (none within the last hour)`}`);
  if (p) console.log(`               ${p.reason}`);
  if (view.acmeTxt.length) console.log(`acme TXT       ${view.acmeTxt.join(" ")}`);
  console.log(`CAA accounts   ${view.caaAccounts.length ? view.caaAccounts.join(" ") : `${MISSING} (any CA may issue)`}`);
  console.log(`answer         ${a.kind} ${a.ips.join(",")}   (${a.reason})`);
  for (const [host, h] of Object.entries(a.hosts)) {
    console.log(`               ${host}.${view.zone}: ${h.kind} ${h.ips.join(",")}   (${h.reason})`);
  }
  console.log("");
  renderTable(
    ["server", "address", "SOA serial"],
    [["primary", "—", primary ? String(primary.serial) : "(no zone)"], ...serials.map((s) => [s.name, s.ip || MISSING, s.serial])]
  );
}

async function delegate(label: string | undefined, onOff: string | undefined): Promise<void> {
  requireUserZones();
  if (onOff !== "on" && onOff !== "off") throw new Error(`usage: mesh-cli dns delegate <user> on|off`);
  const { uid } = await findUser(label);
  await getFirestore().collection(NSL_ROUTER_COLLECTION).doc(uid).update(
    onOff === "on" ? { "dns.delegated": true } : { "dns.delegated": FieldValue.delete() }
  );
  const data = await reload(uid);
  await resyncUser(uid, data);
  const zone = userZoneName(data.domainName);
  const ns = getDnsNsHosts().map((h) => `${zone}. NS ${h}.`);
  if (onOff === "on") {
    console.log(`${zone}: delegated. Its zone is on our nameservers. To make it live, add in the parent zone:`);
    ns.forEach((r) => console.log(`  ${r}`));
  } else {
    console.log(`${zone}: not delegated any more${isDnsShadowZones() ? " (its shadow zone stays)" : "; zone removed"}. Remove from the parent zone:`);
    ns.forEach((r) => console.log(`  ${r}`));
  }
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
  if (result) {
    console.log(`answer ${result.answer.kind} ${result.answer.ips.join(",")} (${result.answer.reason})`);
    result.changed.forEach((c) => console.log(`  ${c}`));
  } else {
    console.log("(not served by our nameservers: setting stored, no zone written)");
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
    const { uid, data } = await findUser(target);
    if (!isInScope(data)) {
      console.log(`${userZoneName(data.domainName)} is not served by our nameservers (not delegated, no shadow zones)`);
      return;
    }
    const r = await syncUser({ uid, label: data.domainName, dns: data.dns }, dryRun);
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
      return;
    }
    initializeFb();
    const r = await syncAllUsers({ refreshScope: true });
    console.log(`user zones: ${r.synced} synced, ${r.probed} probed` +
      `${r.removed.length ? `, removed ${r.removed.join(" ")}` : ""}${r.failed.length ? `, FAILED ${r.failed.join(" ")}` : ""}`);
  }
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

export async function main(argv: string[]): Promise<void> {
  const [sub, arg1, arg2] = positionals(argv);
  switch (sub) {
    case "status": return status(arg1, argv);
    case "delegate": return delegate(arg1, arg2);
    case "force": return force(arg1, arg2, argv);
    case "probe": return probe(arg1);
    case "acme": return acme(arg1);
    case "sync": return sync(arg1, argv);
    case "allow": return allow(argv);
    default:
      console.log(USAGE);
      if (sub) throw new Error(`unknown dns subcommand '${sub}'`);
  }
}
