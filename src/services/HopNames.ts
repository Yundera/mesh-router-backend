import { getRedisClient } from "../redis/redisClient.js";
import { getServerDomain } from "../configuration/config.js";

/**
 * Hop identity: the name a gateway uses as SNI when it connects to a box
 * (<label>.box.<zone>, never in public DNS). Every mesh-CA certificate the backend signs
 * carries it, and gateway 1.6+ derives it from the label itself.
 */

export function hopName(domainName: string): string {
  return `${domainName.toLowerCase()}.box.${getServerDomain()}`;
}

/**
 * PROXY protocol on the hop: the box's Caddy accepts a PROXY v2 header from the gateways
 * (phase-1.1-gateway-tls.md §3), so a gateway passing a connection through raw can hand
 * over the client's address. Reported by the box (mesh-router-caddy) only once its running
 * config carries the listener wrapper; a gateway must not send the header to a box that
 * has not, since it would arrive as garbage before the TLS handshake. Expires unless
 * renewed, so a box rolled back to an older Caddy drops out on its own.
 */
export const PROXY_PROTOCOL_TTL_SECONDS = 2 * 60 * 60;

function proxyProtocolKey(uid: string): string {
  return `hop:proxy:${uid}`;
}

export async function setProxyProtocol(uid: string, enabled: boolean): Promise<void> {
  if (enabled) {
    await getRedisClient().set(proxyProtocolKey(uid), new Date().toISOString(), "EX", PROXY_PROTOCOL_TTL_SECONDS);
  } else {
    await getRedisClient().del(proxyProtocolKey(uid));
  }
}

/** True while the box's last report (within the TTL) said it accepts PROXY v2. */
export async function acceptsProxyProtocol(uid: string): Promise<boolean> {
  return (await getRedisClient().exists(proxyProtocolKey(uid))) === 1;
}
