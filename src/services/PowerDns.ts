import { getPdnsApiKey, getPdnsApiUrl } from "../configuration/config.js";

/**
 * Thin client over the PowerDNS Authoritative HTTP API of the hidden primary
 * (https://doc.powerdns.com/authoritative/http-api/). Names are absolute (trailing dot).
 */

export interface PdnsRecord {
  content: string;
  disabled: boolean;
}

export interface PdnsRRset {
  name: string;
  type: string;
  ttl?: number;
  changetype?: "REPLACE" | "DELETE";
  records: PdnsRecord[];
}

export interface PdnsZone {
  name: string;
  kind: string;
  serial: number;
  catalog?: string;
  rrsets: PdnsRRset[];
}

export class PdnsError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

/** Absolute DNS name: lowercase, one trailing dot. */
export function fqdn(name: string): string {
  return name.toLowerCase().replace(/\.+$/, "") + ".";
}

function baseUrl(): string {
  const url = getPdnsApiUrl();
  if (!url) {
    throw new Error("PDNS_API_URL environment variable is not configured");
  }
  return `${url}/api/v1/servers/localhost`;
}

async function call(method: string, path: string, body?: unknown): Promise<any> {
  const res = await fetch(baseUrl() + path, {
    method,
    headers: { "X-API-Key": getPdnsApiKey(), "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(10_000),
  });
  const text = await res.text();
  if (!res.ok) {
    let detail = text;
    try {
      detail = JSON.parse(text).error ?? text;
    } catch {
      // not JSON
    }
    throw new PdnsError(res.status, `PowerDNS ${method} ${path}: ${res.status} ${detail}`);
  }
  return text ? JSON.parse(text) : undefined;
}

/** Every zone on the primary, without RRsets. */
export async function listZones(): Promise<Omit<PdnsZone, "rrsets">[]> {
  return call("GET", "/zones");
}

/** The zone with its RRsets, or null if the primary does not have it. */
export async function getZone(zone: string): Promise<PdnsZone | null> {
  try {
    return await call("GET", `/zones/${fqdn(zone)}`);
  } catch (e) {
    if (e instanceof PdnsError && (e.status === 404 || e.status === 422)) {
      return null;
    }
    throw e;
  }
}

/**
 * Create a zone. kind "Primary" for a served zone (optionally a member of `catalog`),
 * "Producer" for the catalog itself. The SOA comes from the primary's
 * default-soa-content.
 */
export async function createZone(
  zone: string,
  kind: "Primary" | "Producer",
  options: { catalog?: string; nameservers?: string[] } = {}
): Promise<void> {
  await call("POST", "/zones", {
    name: fqdn(zone),
    kind,
    nameservers: (options.nameservers || []).map(fqdn),
    ...(options.catalog ? { catalog: fqdn(options.catalog) } : {}),
  });
}

export async function deleteZone(zone: string): Promise<void> {
  await call("DELETE", `/zones/${fqdn(zone)}`);
}

/** Apply RRset changes (REPLACE / DELETE) in one transaction; bumps the SOA serial. */
export async function patchRRsets(zone: string, rrsets: PdnsRRset[]): Promise<void> {
  if (rrsets.length === 0) return;
  await call("PATCH", `/zones/${fqdn(zone)}`, { rrsets });
}

/**
 * Send NOTIFY to the zone's secondaries. An API write sends none by itself: without
 * this the secondaries only pick changes up on their refresh cycle.
 */
export async function notifyZone(zone: string): Promise<void> {
  await call("PUT", `/zones/${fqdn(zone)}/notify`);
}
