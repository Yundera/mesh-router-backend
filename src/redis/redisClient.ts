import { Redis } from "ioredis";

let redisClient: Redis | null = null;

/**
 * Returns the Redis URL from environment.
 * @throws Error if REDIS_URL is not configured
 */
export function getRedisUrl(): string {
  const redisUrl = process.env.REDIS_URL;
  if (!redisUrl) {
    throw new Error("REDIS_URL environment variable is not configured");
  }
  return redisUrl;
}

/**
 * Get or create the Redis client singleton.
 * Lazily initializes the connection on first call.
 */
export function getRedisClient(): Redis {
  if (!redisClient) {
    redisClient = new Redis(getRedisUrl(), {
      maxRetriesPerRequest: 3,
      retryStrategy(times) {
        const delay = Math.min(times * 50, 2000);
        return delay;
      },
    });

    redisClient.on("error", (err) => {
      console.error("Redis connection error:", err);
    });

    redisClient.on("connect", () => {
      console.log("Redis connected");
    });
  }

  return redisClient;
}

/**
 * Close the Redis connection gracefully.
 */
export async function closeRedisClient(): Promise<void> {
  if (redisClient) {
    await redisClient.quit();
    redisClient = null;
  }
}
