import { getRedisClient } from "../redis/redisClient.js";
import { getServerDomain } from "../configuration/config.js";

/**
 * Hop identity: the name a gateway uses as SNI when it connects to a box
 * (<label>.box.<zone>, never in public DNS). Every mesh-CA certificate the backend signs
 * carries it; the backend remembers which users currently hold such a certificate so
 * /resolve/v2 announces the name only to gateways that can verify it (a box still on an
 * older certificate keeps the previous SNI until its next renewal, 36 h at most).
 */

function key(uid: string): string {
  return `cert:hop:${uid}`;
}

export function hopName(domainName: string): string {
  return `${domainName.toLowerCase()}.box.${getServerDomain()}`;
}

/** Record that the user's current certificate carries its hop name, until it expires. */
export async function noteHopCert(uid: string, expiresAt: Date): Promise<void> {
  const seconds = Math.floor((expiresAt.getTime() - Date.now()) / 1000);
  if (seconds > 0) {
    await getRedisClient().set(key(uid), expiresAt.toISOString(), "EX", seconds);
  }
}

/** The hop name, when the user's current certificate carries it; null otherwise. */
export async function hopNameFor(uid: string, domainName: string): Promise<string | null> {
  return (await getRedisClient().exists(key(uid))) ? hopName(domainName) : null;
}

export interface HopCoverage {
  // users with live routes, each with its route sources ("agent", "tunnel")
  boxes: { uid: string; sources: string[] }[];
  // those whose current certificate does not carry the hop name yet
  missing: { uid: string; sources: string[] }[];
}

/**
 * Pure: which users with routes (keys `routes:<uid>:<source>`) hold a hop certificate
 * (`hopUids`). A gateway that always sends the hop name (1.6+) reaches only those.
 */
export function hopCoverage(routeKeys: string[], hopUids: Set<string>): HopCoverage {
  const byUid = new Map<string, string[]>();
  for (const k of routeKeys) {
    const m = /^routes:(.+):([^:]+)$/.exec(k);
    if (!m) continue; // routes:sources and other bookkeeping keys
    byUid.set(m[1], [...(byUid.get(m[1]) ?? []), m[2]].sort());
  }
  const boxes = [...byUid].map(([uid, sources]) => ({ uid, sources })).sort((a, b) => a.uid.localeCompare(b.uid));
  return { boxes, missing: boxes.filter((b) => !hopUids.has(b.uid)) };
}

async function scanKeys(pattern: string): Promise<string[]> {
  const redis = getRedisClient();
  const keys: string[] = [];
  let cursor = "0";
  do {
    const [next, batch] = await redis.scan(cursor, "MATCH", pattern, "COUNT", 500);
    cursor = next;
    keys.push(...batch);
  } while (cursor !== "0");
  return keys;
}

/** Hop-name coverage of every box with live routes (mesh-cli dns hops). */
export async function getHopCoverage(): Promise<HopCoverage> {
  const [routeKeys, hopKeys] = await Promise.all([scanKeys("routes:*"), scanKeys(key("*"))]);
  return hopCoverage(routeKeys, new Set(hopKeys.map((k) => k.slice(key("").length))));
}
