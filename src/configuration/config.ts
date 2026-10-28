/**
 * Returns the SERVER_DOMAIN from environment.
 * This is the domain suffix used for all user domains (e.g., "nsl.sh", "inojob.com").
 * @throws Error if SERVER_DOMAIN is not configured
 */
export function getServerDomain(): string {
  const serverDomain = process.env.SERVER_DOMAIN;
  if (!serverDomain) {
    throw new Error("SERVER_DOMAIN environment variable is not configured");
  }
  return serverDomain;
}

/**
 * Returns extra DNS names every box certificate carries as SANs, from CERT_EXTRA_SANS
 * (comma-separated, e.g. "*.ip.inojob.com"). Empty when unset.
 * For names a deployment's boxes answer on beyond their hop name, so each deployment
 * states its own without a code change.
 */
export function getCertExtraSans(): string[] {
  return (process.env.CERT_EXTRA_SANS || "")
    .split(",")
    .map((name) => name.trim())
    .filter((name) => name !== "");
}

/**
 * Returns the SendGrid API key used by the per-user mail relay (POST /email/send),
 * or undefined if mail sending is not configured. When undefined, sends are skipped
 * (logged) rather than failing, so non-mail deployments and local dev still work.
 * The SendGrid sending domain must match SERVER_DOMAIN (e.g. nsl.sh) with DKIM/SPF/DMARC.
 */
export function getSendgridApiKey(): string | undefined {
  return process.env.SENDGRID_API_KEY || undefined;
}

/**
 * Default TTL for route entries in seconds.
 */
const DEFAULT_ROUTES_TTL_SECONDS = 600; // 10 minutes

/**
 * Default number of days of inactivity before a domain is considered inactive.
 */
const DEFAULT_INACTIVE_DOMAIN_DAYS = 30;

/**
 * Default path for domain events audit log.
 */
const DEFAULT_DOMAIN_LOG_PATH = "logs/domain-events.log";

/**
 * Default cron schedule for domain cleanup (3 AM daily).
 */
const DEFAULT_CLEANUP_CRON_SCHEDULE = "0 3 * * *";

/**
 * Default retention for usage (DAU) daily buckets in seconds (90 days).
 */
const DEFAULT_USAGE_RETENTION_SECONDS = 90 * 24 * 60 * 60; // 7776000

/**
 * Returns the number of days of inactivity before a domain is considered inactive.
 * @returns Number of days
 */
export function getInactiveDomainDays(): number {
  const envValue = process.env.INACTIVE_DOMAIN_DAYS;
  if (envValue) {
    const parsed = parseInt(envValue, 10);
    if (!isNaN(parsed) && parsed > 0) {
      return parsed;
    }
  }
  return DEFAULT_INACTIVE_DOMAIN_DAYS;
}

/**
 * Returns the path for domain events audit log.
 * @returns File path
 */
export function getDomainLogPath(): string {
  return process.env.DOMAIN_LOG_PATH || DEFAULT_DOMAIN_LOG_PATH;
}

/**
 * Returns the cron schedule for domain cleanup.
 * @returns Cron schedule string
 */
export function getCleanupCronSchedule(): string {
  return process.env.CLEANUP_CRON_SCHEDULE || DEFAULT_CLEANUP_CRON_SCHEDULE;
}

/**
 * Returns the TTL for route entries from environment or default.
 * Routes expire if not refreshed within this time.
 * @returns TTL in seconds
 */
export function getRoutesTtl(): number {
  const envValue = process.env.ROUTES_TTL_SECONDS;
  if (envValue) {
    const parsed = parseInt(envValue, 10);
    if (!isNaN(parsed) && parsed > 0) {
      return parsed;
    }
  }
  return DEFAULT_ROUTES_TTL_SECONDS;
}

/**
 * Returns the retention for usage (DAU) daily buckets from environment or default.
 * Each usage:* daily key expires after this many seconds (rolling ~90 day window).
 * @returns Retention in seconds
 */
export function getUsageRetentionSeconds(): number {
  const envValue = process.env.USAGE_RETENTION_SECONDS;
  if (envValue) {
    const parsed = parseInt(envValue, 10);
    if (!isNaN(parsed) && parsed > 0) {
      return parsed;
    }
  }
  return DEFAULT_USAGE_RETENTION_SECONDS;
}

/**
 * Default grace period for the ip.<zone> allowlist in seconds (6 hours): an IP stays
 * answerable this long after its agent last registered it.
 */
const DEFAULT_DNS_ALLOW_GRACE_SECONDS = 6 * 60 * 60; // 21600

/**
 * Returns the PowerDNS hidden primary's API base URL (e.g. "http://pdns-primary:8081"),
 * or undefined when unset. Unset disables every DNS write (DnsZones.ts).
 */
export function getPdnsApiUrl(): string | undefined {
  return process.env.PDNS_API_URL?.replace(/\/+$/, "") || undefined;
}

/**
 * Returns the PowerDNS API key (X-API-Key header).
 */
export function getPdnsApiKey(): string {
  return process.env.PDNS_API_KEY || "";
}

/**
 * Returns the ip.<zone> name served by the nameserver secondaries (e.g. "ip.inojob.com"),
 * without trailing dot, or undefined when unset. Its allowlist zone is
 * allow.<ip-zone>.invalid (mesh-router-nameserver deploy/secondary/lua/ipname.lua).
 */
export function getDnsIpZone(): string | undefined {
  return process.env.DNS_IP_ZONE?.replace(/\.+$/, "").toLowerCase() || undefined;
}

/**
 * Returns the catalog (RFC 9432) producer zone the backend's zones are members of, so
 * the secondaries pick them up. Default catalog.<SERVER_DOMAIN>.invalid.
 */
export function getDnsCatalogZone(): string {
  const name = process.env.DNS_CATALOG_ZONE || `catalog.${getServerDomain()}.invalid`;
  return name.replace(/\.+$/, "").toLowerCase();
}

/**
 * Returns the ip.<zone> allowlist grace period from environment or default.
 * @returns Grace in seconds
 */
export function getDnsAllowGraceSeconds(): number {
  const envValue = process.env.DNS_ALLOW_GRACE_SECONDS;
  if (envValue) {
    const parsed = parseInt(envValue, 10);
    if (!isNaN(parsed) && parsed > 0) {
      return parsed;
    }
  }
  return DEFAULT_DNS_ALLOW_GRACE_SECONDS;
}

function commaList(value: string | undefined): string[] {
  return (value || "")
    .split(",")
    .map((item) => item.trim().replace(/\.+$/, "").toLowerCase())
    .filter((item) => item !== "");
}

/**
 * Returns the gateway's public IPv4s, from DNS_GATEWAY_IPS (comma-separated): what a
 * user's names answer when the box can't serve them itself. Empty when unset.
 */
export function getDnsGatewayIps(): string[] {
  return commaList(process.env.DNS_GATEWAY_IPS);
}

/**
 * Returns the public nameserver names (NS records of every user zone), from
 * DNS_NS_HOSTS (comma-separated, no trailing dots). Empty when unset.
 */
export function getDnsNsHosts(): string[] {
  return commaList(process.env.DNS_NS_HOSTS);
}

/**
 * True when DNS_SHADOW_ZONES=1: every active user gets a zone on the nameservers, not
 * only delegated ones. Without a delegation no resolver asks for those zones, so they
 * only serve `dig @<ns>` checks of the answer rule.
 */
export function isDnsShadowZones(): boolean {
  return process.env.DNS_SHADOW_ZONES === "1";
}
