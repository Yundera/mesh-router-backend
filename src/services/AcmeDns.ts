import { getRedisClient } from "../redis/redisClient.js";
import { getServerDomain } from "../configuration/config.js";

/**
 * DNS-01 challenge store behind the acme-dns API (mesh-router-nameserver architecture
 * §7.2). A box sets `_acme-challenge.<label>.<zone>` TXT through POST /acme-dns/update
 * (acme-dns protocol, credential = its Ed25519 signature); a lego-based client through
 * httpreq (/acme-dns/present, /cleanup). DnsZones writes the live values into the user's
 * zone on the hidden primary.
 */

/** A value lives this long, then the full pass removes it from the zone. */
export const ACME_TXT_LIFETIME_MS = 10 * 60 * 1000;
/** Two per box order (the wildcard and the apex validate together), plus one per gateway
 * ordering the user's fallback *.<label>.<zone> in the same window; at the apex, the
 * gateways' own *.<zone> orders. */
const MAX_VALUES = 8;
const RATE_LIMIT = 10;
const RATE_WINDOW_SECONDS = 60 * 60;

/** A DNS-01 challenge value: base64url SHA-256, 43 characters. */
export function isAcmeTxtValue(txt: unknown): txt is string {
  return typeof txt === "string" && /^[A-Za-z0-9_-]{43}$/.test(txt);
}

/**
 * The user label of a lego httpreq fqdn `_acme-challenge.<label>.<SERVER_DOMAIN>.`, or
 * null for any other name.
 */
export function acmeLabelFromFqdn(fqdn: unknown): string | null {
  if (typeof fqdn !== "string") return null;
  const name = fqdn.toLowerCase().replace(/\.+$/, "");
  const suffix = `.${getServerDomain().toLowerCase()}`;
  const prefix = "_acme-challenge.";
  if (!name.startsWith(prefix) || !name.endsWith(suffix)) return null;
  const label = name.slice(prefix.length, -suffix.length);
  return /^[a-z0-9-]+$/.test(label) ? label : null;
}

/**
 * The key the apex challenge `_acme-challenge.<SERVER_DOMAIN>` is stored under: the
 * gateways' own *.<zone> orders (phase-1.1-gateway-tls.md §6.1). Not a valid user label,
 * so it never collides with one.
 */
export const APEX_ACME_LABEL = "@";

/** True for lego's httpreq fqdn `_acme-challenge.<SERVER_DOMAIN>.` (any case, dot optional). */
export function isApexAcmeFqdn(fqdn: unknown): boolean {
  if (typeof fqdn !== "string") return false;
  return fqdn.toLowerCase().replace(/\.+$/, "") === `_acme-challenge.${getServerDomain().toLowerCase()}`;
}

function txtKey(label: string): string {
  return `acme:txt:${label.toLowerCase()}`;
}

/** Live values for a label, oldest first, with the time each was set (ms). */
export async function listAcmeTxt(label: string, now = Date.now()): Promise<{ value: string; at: number }[]> {
  const raw = await getRedisClient().zrangebyscore(txtKey(label), now - ACME_TXT_LIFETIME_MS, "+inf", "WITHSCORES");
  const out: { value: string; at: number }[] = [];
  for (let i = 0; i < raw.length; i += 2) out.push({ value: raw[i], at: Number(raw[i + 1]) });
  return out;
}

/** The values the zone should publish. */
export async function getAcmeTxt(label: string): Promise<string[]> {
  return (await listAcmeTxt(label)).map((v) => v.value);
}

/** Add a value: keeps the newest MAX_VALUES, drops expired ones. */
export async function addAcmeTxt(label: string, value: string, now = Date.now()): Promise<void> {
  const key = txtKey(label);
  await getRedisClient()
    .multi()
    .zadd(key, now, value)
    .zremrangebyscore(key, "-inf", now - ACME_TXT_LIFETIME_MS)
    .zremrangebyrank(key, 0, -(MAX_VALUES + 1))
    .pexpire(key, ACME_TXT_LIFETIME_MS)
    .exec();
}

export async function removeAcmeTxt(label: string, value: string): Promise<void> {
  await getRedisClient().zrem(txtKey(label), value);
}

function rateKey(uid: string): string {
  return `acme:rate:${uid}`;
}

/** Count one update; false once the key is past its limit (RATE_LIMIT for a box) within the window. */
export async function takeAcmeUpdate(uid: string, limit = RATE_LIMIT): Promise<boolean> {
  const redis = getRedisClient();
  const count = await redis.incr(rateKey(uid));
  if (count === 1) await redis.expire(rateKey(uid), RATE_WINDOW_SECONDS);
  return count <= limit;
}

/** The rate-limit key of a gateway credential (apex and user challenges alike). */
export function gatewayRateKey(gateway: string | undefined): string {
  return `gateway:${gateway ?? "service"}`;
}

/** Updates used in the current window, and seconds until it resets. */
export async function acmeRateState(uid: string): Promise<{ used: number; limit: number; resetsIn: number }> {
  const redis = getRedisClient();
  const [used, ttl] = await Promise.all([redis.get(rateKey(uid)), redis.ttl(rateKey(uid))]);
  return { used: Number(used || 0), limit: RATE_LIMIT, resetsIn: Math.max(ttl, 0) };
}
