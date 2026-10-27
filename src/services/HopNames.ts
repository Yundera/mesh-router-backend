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
