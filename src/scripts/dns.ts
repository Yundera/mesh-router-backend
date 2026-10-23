/**
 * mesh-cli dns <subcommand>
 *
 *   dns allow [--json]       ip.<zone> allowlist: IPs, last registration, expiry
 *   dns sync [--dry-run]     run the allowlist reconcile now and print what changed
 *
 * Talks to Redis and the PowerDNS hidden primary with the backend's own env
 * (REDIS_URL, PDNS_API_URL, PDNS_API_KEY, DNS_IP_ZONE).
 */
import { allowZoneName, isDnsEnabled, listAllowed, syncAllow } from "../services/DnsZones.js";
import { getDnsAllowGraceSeconds } from "../configuration/config.js";
import { hasFlag, positionals, renderTable } from "../cli/format.js";

function usage(): void {
  console.log("Usage: mesh-cli dns allow [--json] | dns sync [--dry-run]");
}

export async function main(argv: string[]): Promise<void> {
  const [sub] = positionals(argv);
  if (!isDnsEnabled()) {
    throw new Error("DNS is not configured: PDNS_API_URL and DNS_IP_ZONE must be set");
  }

  if (sub === "allow") {
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
    return;
  }

  if (sub === "sync") {
    const dryRun = hasFlag(argv, "dry-run");
    const r = await syncAllow(dryRun);
    const line = (label: string, items: string[]) =>
      console.log(`${label.padEnd(8)} ${items.length ? items.join(" ") : "—"}`);
    if (dryRun) console.log("(dry run: nothing written)");
    line("created", r.created);
    line("expired", r.pruned);
    line("added", r.added);
    line("removed", r.removed);
    return;
  }

  usage();
  if (sub) throw new Error(`unknown dns subcommand '${sub}'`);
}
