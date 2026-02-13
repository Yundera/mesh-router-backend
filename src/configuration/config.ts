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
