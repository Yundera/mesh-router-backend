import { getRedisClient } from "../redis/redisClient.js";
import { getRoutesTtl, getInactiveDomainDays } from "../configuration/config.js";

/**
 * Redis key for domain activity tracking sorted set.
 * Stores userId -> timestamp (score) mapping for fast activity queries.
 */
const ACTIVITY_KEY = "domains:activity";

/**
 * Health check configuration for a route.
 */
export interface RouteHealthCheck {
  path: string;        // HTTP path to probe (e.g., "/.well-known/health")
  host?: string;       // Optional Host header override (defaults to user's domain)
}

/**
 * A single route entry for reaching a PCS.
 */
export interface Route {
  ip: string;                      // IP address of the route endpoint
  port: number;                    // Port number
  priority: number;                // Lower number = higher priority (1 = direct, 2 = tunnel)
  scheme?: "http" | "https";       // Protocol scheme (default: "https" for backward compat)
  healthCheck?: RouteHealthCheck;  // Optional health check configuration
  source: string;                  // Source identifier (e.g., "agent", "tunnel") - routes from same source replace each other
  type?: "ip" | "domain";          // Route type: "ip" for direct IP, "domain" for pre-validated domain routes (default: "ip")
  domain?: string;                 // Domain hostname (required when type="domain", e.g., "88-187-147-189.sslip.io")
}

/**
 * In-memory set of known route sources.
 * Populated as sources register - avoids expensive Redis KEYS scans.
 * Self-repopulates after restart as sources re-register (every 5 min).
 */
const knownSources = new Set<string>();

/**
 * Get the Redis key for a specific source's routes.
 */
function getSourceRoutesKey(userId: string, source: string): string {
  return `routes:${userId}:${source}`;
}

/**
 * Get all source keys for a user based on known sources.
 */
function getAllSourceKeys(userId: string): string[] {
  return Array.from(knownSources).map(s => getSourceRoutesKey(userId, s));
}

/**
 * Register or update routes for a user.
 * Routes are stored in separate Redis keys per source, each with independent TTL.
 * This prevents one source from refreshing another source's TTL.
 *
 * @param userId - The user ID
 * @param routes - Array of routes to register/update
 */
export async function registerRoutes(userId: string, routes: Route[]): Promise<void> {
  if (!userId) {
    throw new Error("User ID is required.");
  }

  if (!routes || routes.length === 0) {
    throw new Error("At least one route is required.");
  }

  // Validate routes
  for (const route of routes) {
    if (!route.ip) {
      throw new Error("Route IP is required.");
    }
    if (!route.port || route.port < 1 || route.port > 65535) {
      throw new Error("Route port must be between 1 and 65535.");
    }
    if (typeof route.priority !== "number") {
      throw new Error("Route priority is required.");
    }
    if (!route.source) {
      throw new Error("Route source is required.");
    }
  }

  // Group routes by source and track known sources
  const routesBySource = new Map<string, Route[]>();
  for (const route of routes) {
    knownSources.add(route.source);
    const existing = routesBySource.get(route.source) || [];
    existing.push(route);
    routesBySource.set(route.source, existing);
  }

  const redis = getRedisClient();
  const pipeline = redis.pipeline();

  // Write each source's routes to its own key with independent TTL
  for (const [source, sourceRoutes] of routesBySource) {
    const key = getSourceRoutesKey(userId, source);
    pipeline.setex(key, getRoutesTtl(), JSON.stringify(sourceRoutes));
  }

  await pipeline.exec();

  // Update activity tracking in Redis
  await updateActivityTracking(userId);
}

/**
 * Get routes for a user.
 * Merges routes from all source-specific keys.
 *
 * @param userId - The user ID
 * @returns Array of routes, or null if not found/expired
 */
export async function getRoutes(userId: string): Promise<Route[] | null> {
  if (!userId) {
    throw new Error("User ID is required.");
  }

  const redis = getRedisClient();
  const keys = getAllSourceKeys(userId);

  if (keys.length === 0) {
    return null;
  }

  // Use MGET for single round-trip
  const values = await redis.mget(...keys);

  const allRoutes: Route[] = [];
  for (const value of values) {
    if (value) {
      try {
        const routes = JSON.parse(value) as Route[];
        allRoutes.push(...routes);
      } catch {
        // Skip invalid data
      }
    }
  }

  return allRoutes.length > 0 ? allRoutes : null;
}

/**
 * Delete routes for a user.
 * Deletes all source-specific keys.
 *
 * @param userId - The user ID
 */
export async function deleteRoutes(userId: string): Promise<void> {
  if (!userId) {
    throw new Error("User ID is required.");
  }

  const redis = getRedisClient();
  const keys = getAllSourceKeys(userId);

  // Delete all source keys (del ignores non-existent keys)
  if (keys.length > 0) {
    await redis.del(...keys);
  }
}

/**
 * Check if a user has any routes registered.
 * Checks all source-specific keys.
 *
 * @param userId - The user ID
 * @returns true if routes exist, false otherwise
 */
export async function hasRoutes(userId: string): Promise<boolean> {
  if (!userId) {
    throw new Error("User ID is required.");
  }

  const redis = getRedisClient();
  const keys = getAllSourceKeys(userId);

  // No known sources means no routes possible
  if (keys.length === 0) {
    return false;
  }

  // Check if any source key exists for this user
  const exists = await redis.exists(...keys);

  return exists > 0;
}

/**
 * Get the TTL (time to live) for a user's routes.
 * Returns the minimum positive TTL across all source keys.
 *
 * @param userId - The user ID
 * @returns TTL in seconds, -2 if no keys exist
 */
export async function getRoutesTTL(userId: string): Promise<number> {
  if (!userId) {
    throw new Error("User ID is required.");
  }

  const redis = getRedisClient();
  const keys = getAllSourceKeys(userId);

  // No known sources means no routes possible
  if (keys.length === 0) {
    return -2;
  }

  // Get TTL for all source keys
  const pipeline = redis.pipeline();
  for (const key of keys) {
    pipeline.ttl(key);
  }
  const results = await pipeline.exec();

  // Return minimum positive TTL, or -2 if no keys exist
  let minTtl = -2;
  for (const result of results || []) {
    const [err, ttl] = result as [Error | null, number];
    if (!err && typeof ttl === 'number' && ttl > 0) {
      if (minTtl === -2 || ttl < minTtl) {
        minTtl = ttl;
      }
    }
  }

  return minTtl;
}

// ============================================================================
// Domain Activity Tracking
// ============================================================================

/**
 * Update activity tracking for a user.
 * Called when routes are registered to track the last activity time.
 *
 * @param userId - The user ID
 */
export async function updateActivityTracking(userId: string): Promise<void> {
  if (!userId) {
    throw new Error("User ID is required.");
  }

  const redis = getRedisClient();
  await redis.zadd(ACTIVITY_KEY, Date.now(), userId);
}

/**
 * Get user IDs that have been active within the specified number of days.
 *
 * @param inactiveDays - Number of days to consider active (default: from config)
 * @returns Array of user IDs that are active
 */
export async function getActiveUserIds(inactiveDays?: number): Promise<string[]> {
  const days = inactiveDays ?? getInactiveDomainDays();
  const threshold = Date.now() - (days * 24 * 60 * 60 * 1000);

  const redis = getRedisClient();
  return redis.zrangebyscore(ACTIVITY_KEY, threshold, '+inf');
}

/**
 * Get user IDs that have been inactive for more than the specified number of days.
 *
 * @param inactiveDays - Number of days of inactivity (default: from config)
 * @returns Array of user IDs that are inactive
 */
export async function getInactiveUserIds(inactiveDays?: number): Promise<string[]> {
  const days = inactiveDays ?? getInactiveDomainDays();
  const threshold = Date.now() - (days * 24 * 60 * 60 * 1000);

  const redis = getRedisClient();
  return redis.zrangebyscore(ACTIVITY_KEY, 0, threshold);
}

/**
 * Remove a user from activity tracking.
 * Called during domain cleanup.
 *
 * @param userId - The user ID to remove
 */
export async function removeFromActivityTracking(userId: string): Promise<void> {
  if (!userId) {
    throw new Error("User ID is required.");
  }

  const redis = getRedisClient();
  await redis.zrem(ACTIVITY_KEY, userId);
}

/**
 * Get the last activity timestamp for a user.
 *
 * @param userId - The user ID
 * @returns Timestamp in milliseconds, or null if not found
 */
export async function getActivityTimestamp(userId: string): Promise<number | null> {
  if (!userId) {
    throw new Error("User ID is required.");
  }

  const redis = getRedisClient();
  const score = await redis.zscore(ACTIVITY_KEY, userId);

  return score !== null ? parseInt(score, 10) : null;
}
