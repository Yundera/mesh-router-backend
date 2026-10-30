import { getRedisClient } from "../redis/redisClient.js";
import { getUsageRetentionSeconds } from "../configuration/config.js";

/**
 * App-usage (DAU) tracking.
 *
 * The unit of record is a distinct (uid, app, day) tuple — one Daily Active User
 * signal per app per user per UTC day. Raw request counts are intentionally NOT
 * tracked. The boxes report it themselves (POST /usage/:userid/:sig): each one's
 * mesh-router-agent reads its Caddy access log and sends the set of apps opened
 * that day whenever it grows. Because every write below is a SADD, re-sending a
 * set (agent restart, retry after a failure) is idempotent.
 *
 * Redis keys (all SET, each EXPIRE'd to the rolling retention window):
 *   usage:dau:{app}:{date}   SET<uid>   per-app DAU
 *   usage:apps:{date}        SET<app>   apps active that day (enumeration without SCAN)
 *   usage:active:{date}      SET<uid>   global DAU across all apps
 *   usage:user:{uid}:{date}  SET<app>   apps a user touched (not surfaced in v1)
 *
 * {date} is the UTC calendar day of the visit. The box names it, so the set it flushes
 * after midnight still lands on the day it was collected; isReportableDate() keeps a
 * box from writing anywhere but today and yesterday.
 */

export interface UsageEvent {
  uid: string;
  app: string;
}

/** Maximum apps accepted in a single report (abuse guard). */
export const MAX_USAGE_EVENTS_PER_REQUEST = 100;

/** An app name as a box reports it: a host label, or `_root` / `_custom`. */
const APP_NAME = /^[a-z0-9_][a-z0-9-]{0,62}$/;

/**
 * Whether a reported app name is well-formed. Anything else is dropped by the
 * caller rather than stored as a Redis key fragment.
 */
export function isValidAppName(app: unknown): app is string {
  return typeof app === "string" && APP_NAME.test(app);
}

/**
 * Format a Date as a UTC calendar day string (YYYY-MM-DD).
 */
export function utcDateString(date: Date = new Date()): string {
  return date.toISOString().slice(0, 10);
}

/**
 * Whether a box may report usage for `date`: today or yesterday (UTC). Yesterday is
 * the set a box flushes after midnight; anything older (or in the future) would let a
 * box rewrite history.
 *
 * @param date - Day the box reports for (YYYY-MM-DD)
 * @param now - Current time (default: now)
 */
export function isReportableDate(date: unknown, now: Date = new Date()): date is string {
  if (typeof date !== "string") {
    return false;
  }
  const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  return date === utcDateString(now) || date === utcDateString(yesterday);
}

function dauKey(app: string, date: string): string {
  return `usage:dau:${app}:${date}`;
}

function appsKey(date: string): string {
  return `usage:apps:${date}`;
}

function activeKey(date: string): string {
  return `usage:active:${date}`;
}

function userKey(uid: string, date: string): string {
  return `usage:user:${uid}:${date}`;
}

/**
 * Record one or more (uid, app) usage events for a UTC day.
 * Idempotent: re-recording the same tuple within the day is a no-op on cardinality.
 *
 * @param events - Array of {uid, app} events
 * @param date - UTC day the events belong to (default: today)
 */
export async function recordUsage(events: UsageEvent[], date: string = utcDateString()): Promise<void> {
  if (!events || events.length === 0) {
    return;
  }

  const ttl = getUsageRetentionSeconds();
  const redis = getRedisClient();
  const pipeline = redis.pipeline();

  // De-dup keys we EXPIRE so we don't issue redundant EXPIREs in one batch.
  const expired = new Set<string>();
  const expire = (key: string) => {
    if (!expired.has(key)) {
      pipeline.expire(key, ttl);
      expired.add(key);
    }
  };

  for (const { uid, app } of events) {
    pipeline.sadd(dauKey(app, date), uid);
    expire(dauKey(app, date));

    pipeline.sadd(appsKey(date), app);
    expire(appsKey(date));

    pipeline.sadd(activeKey(date), uid);
    expire(activeKey(date));

    pipeline.sadd(userKey(uid, date), app);
    expire(userKey(uid, date));
  }

  await pipeline.exec();
}

/**
 * Generate UTC day strings for the last `days` days, ending at (and including) `endDate`.
 * Newest first is irrelevant for set unions; order does not matter.
 *
 * @param days - Window size (>= 1)
 * @param endDate - Last day in the window (default: today UTC)
 */
export function dateWindow(days: number, endDate: Date = new Date()): string[] {
  const span = Math.max(1, Math.floor(days));
  const dates: string[] = [];
  for (let i = 0; i < span; i++) {
    const d = new Date(endDate.getTime() - i * 24 * 60 * 60 * 1000);
    dates.push(utcDateString(d));
  }
  return dates;
}

/**
 * Count distinct active users for an app across the given days.
 * 1 day = DAU; 7 days = WAU; 30 days = MAU.
 *
 * @param app - App name (leftmost host label, e.g. "nextcloud")
 * @param dates - UTC day strings to union over
 * @returns Distinct uid count
 */
export async function getAppActiveUsers(app: string, dates: string[]): Promise<number> {
  if (dates.length === 0) {
    return 0;
  }
  const redis = getRedisClient();
  if (dates.length === 1) {
    return redis.scard(dauKey(app, dates[0]));
  }
  // SUNION returns the merged members; count distinct without a temp key.
  const members = await redis.sunion(...dates.map((d) => dauKey(app, d)));
  return members.length;
}

/**
 * List app names active on a given day.
 *
 * @param date - UTC day string
 */
export async function getActiveAppsForDate(date: string): Promise<string[]> {
  const redis = getRedisClient();
  return redis.smembers(appsKey(date));
}

/**
 * List app names active across any of the given days.
 *
 * @param dates - UTC day strings
 */
export async function getActiveApps(dates: string[]): Promise<string[]> {
  if (dates.length === 0) {
    return [];
  }
  const redis = getRedisClient();
  const members = await redis.sunion(...dates.map((d) => appsKey(d)));
  return members;
}

/**
 * Count distinct global active users across the given days.
 *
 * @param dates - UTC day strings
 */
export async function getGlobalActiveUsers(dates: string[]): Promise<number> {
  if (dates.length === 0) {
    return 0;
  }
  const redis = getRedisClient();
  if (dates.length === 1) {
    return redis.scard(activeKey(dates[0]));
  }
  const members = await redis.sunion(...dates.map((d) => activeKey(d)));
  return members.length;
}

export interface AppUsage {
  app: string;
  activeUsers: number;
}

/**
 * Rank apps by distinct active users across the given days, descending.
 *
 * @param dates - UTC day strings
 * @param limit - Max apps to return (0 = no limit)
 * @returns Sorted [{app, activeUsers}], highest first
 */
export async function getTopApps(dates: string[], limit = 0): Promise<AppUsage[]> {
  const apps = await getActiveApps(dates);
  const ranked: AppUsage[] = [];
  for (const app of apps) {
    ranked.push({ app, activeUsers: await getAppActiveUsers(app, dates) });
  }
  ranked.sort((a, b) => b.activeUsers - a.activeUsers || a.app.localeCompare(b.app));
  return limit > 0 ? ranked.slice(0, limit) : ranked;
}
