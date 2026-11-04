import * as tls from "tls";
import * as https from "https";
import * as http from "http";
import { getDnsGatewayIps, getDnsGatewayTunnels, getServerDomain, GatewayTunnel } from "../configuration/config.js";

/**
 * Health of the gateways in DNS_GATEWAY_IPS, so a dead one leaves the gateway answers
 * (mesh-router-nameserver docs/architecture.md §12, "One gateway down"), and of the
 * tunnel provider next to each (DNS_GATEWAY_TUNNELS), so a NAT box is only answered by
 * gateways that can reach it (docs/multi-gateway.md, "Per-box gateway set").
 *
 * Every INTERVAL_MS each gateway gets one TLS handshake on :443 with SNI
 * gateway.entrypoint.<zone>: a name the gateway always terminates itself (self-signed,
 * not verified), so the check is the same whether the gateway is the edge or sits
 * behind a TCP passthrough. Each provider with a URL gets GET <url>/api/ping. A check
 * goes down after FALL failed checks in a row and back up after RISE good ones; every
 * check starts up.
 *
 * healthyGatewayIps() is what the apex answers: the healthy gateways, or all of them
 * when none is (a wrong probe must never empty the answer). boxGatewayIps() narrows it
 * for a NAT box. The full list stays what boxes trust for PROXY headers (/version
 * gatewayIps): a gateway that comes back must not find itself distrusted.
 *
 * A dead provider only takes its gateway out of NAT boxes' answers: the gateway still
 * reaches boxes with a public IP.
 *
 * The same handshake reads the certificate the gateway presents for the names it
 * terminates: its public *.<zone> (phase-1.1-gateway-tls.md §6.1) or the self-signed
 * fallback. Kept on the state for /dns/health (gatewayCertProblem), never verified here:
 * a bad certificate never takes a gateway out of the answers.
 *
 * In memory: one backend, and a restart starts from "all up", the safe side.
 */

const INTERVAL_MS = 15_000;
const TIMEOUT_MS = 5_000;
const FALL = 2;
const RISE = 2;

/** What a gateway presented on the last handshake that completed. */
export interface GatewayCert {
  notAfter: string;
  issuer: string;
  /** subjectAltName DNS names */
  names: string[];
  selfSigned: boolean;
}

export interface GatewayState {
  ip: string;
  up: boolean;
  /** consecutive checks against the current state */
  streak: number;
  lastError?: string;
  lastCheck?: string;
  changedAt?: string;
  /** the gateway's local tunnel provider, when DNS_GATEWAY_TUNNELS gives its URL */
  tunnel?: GatewayState;
  /** the certificate it presented on the last completed handshake */
  cert?: GatewayCert;
}

const states = new Map<string, GatewayState>();
const tunnelStates = new Map<string, GatewayState>();

/** One check result applied to a state (FALL/RISE hysteresis). Pure. */
export function nextState(state: GatewayState, ok: boolean, error: string | undefined, now: Date): GatewayState {
  const next: GatewayState = { ...state, lastCheck: now.toISOString(), lastError: ok ? undefined : error };
  if (ok === state.up) {
    next.streak = 0;
    return next;
  }
  next.streak = state.streak + 1;
  if (next.streak >= (state.up ? FALL : RISE)) {
    next.up = ok;
    next.streak = 0;
    next.changedAt = now.toISOString();
  }
  return next;
}

/** The answer set from the states: the healthy ones, else all (fail open). Pure. */
export function pickHealthy(ips: string[], up: (ip: string) => boolean): string[] {
  const healthy = ips.filter(up);
  return healthy.length ? healthy : ips;
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return null;
  return ((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3];
}

/** True when `ip` is inside `cidr` (IPv4 a.b.c.d/n). Pure. */
export function inSubnet(ip: string, cidr: string): boolean {
  const [net, bits] = cidr.split("/");
  const n = ipv4ToInt(net);
  const a = ipv4ToInt(ip);
  const prefix = Number(bits);
  if (n === null || a === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
  const block = 2 ** (32 - prefix);
  return Math.floor(a / block) === Math.floor(n / block);
}

/**
 * The gateways for a NAT box: of `healthy`, those whose tunnel subnet holds one of the
 * box's tunnel addresses, preferring the ones whose provider is up. Falls back to the
 * reaching ones when all their providers are down, and to `healthy` when no gateway's
 * subnet matches (no tunnel mapping, an offline box, a box without tunnelIp). Pure.
 */
export function pickForBox(
  healthy: string[], tunnels: GatewayTunnel[], tunnelUp: (ip: string) => boolean, tunnelIps: string[],
): string[] {
  if (!tunnels.length || !tunnelIps.length) return healthy;
  const reach = healthy.filter((ip) => tunnels.some((t) => t.ip === ip && tunnelIps.some((a) => inSubnet(a, t.subnet))));
  if (!reach.length) return healthy;
  const up = reach.filter(tunnelUp);
  return up.length ? up : reach;
}

function stateOf(ip: string): GatewayState {
  return states.get(ip) ?? { ip, up: true, streak: 0 };
}

function tunnelStateOf(ip: string): GatewayState {
  return tunnelStates.get(ip) ?? { ip, up: true, streak: 0 };
}

/** The gateway IPs answered for a box that can serve the gateway's way, right now. */
export function healthyGatewayIps(): string[] {
  return pickHealthy(getDnsGatewayIps(), (ip) => stateOf(ip).up);
}

/**
 * The gateway IPs a user's names answer right now: all healthy ones for a box with a
 * public IP (every gateway reaches it), only those reaching its tunnel otherwise.
 * `tunnelIps` are the box's tunnel addresses (tunnelIp of its tunnel routes).
 */
export function boxGatewayIps(publicIp: string | null, tunnelIps: string[]): string[] {
  const healthy = healthyGatewayIps();
  if (publicIp) return healthy;
  return pickForBox(healthy, getDnsGatewayTunnels(), (ip) => tunnelStateOf(ip).up, tunnelIps);
}

/** A route as /resolve/v2 hands it to the gateways (the fields this file reads or adds). */
export interface GatewayRoute {
  source: string;
  tunnelIp?: string;
  /** the gateway whose local provider holds tunnelIp (added for the gateways' handoff) */
  gateway?: string;
}

/**
 * The routes as the gateways get them (/resolve/v2), for the handoff between gateways
 * (docs/multi-gateway.md, "Handoff"): each tunnel route is tagged with the gateway whose
 * provider holds its tunnelIp, so a gateway that cannot reach the box itself knows which
 * gateway can; and a tunnel route through a provider that is down is dropped, so that
 * provider's gateway hands the request over instead of trying a dead tunnel. When every
 * tagged tunnel route would go, none is dropped (a wrong probe must never leave the box
 * unreachable, the same fail-open as the answers). Pure.
 */
export function routesForGateways<T extends GatewayRoute>(
  routes: T[], tunnels: GatewayTunnel[], tunnelUp: (ip: string) => boolean,
): (T & { gateway?: string })[] {
  if (!tunnels.length) return routes;
  const tagged: (T & { gateway?: string })[] = routes.map((r) => {
    if (r.source !== "tunnel" || typeof r.tunnelIp !== "string") return r;
    const t = tunnels.find((tun) => inSubnet(r.tunnelIp as string, tun.subnet));
    return t ? { ...r, gateway: t.ip } : r;
  });
  const kept = tagged.filter((r) => !r.gateway || tunnelUp(r.gateway));
  const taggedLeft = kept.some((r) => r.gateway);
  return taggedLeft || !tagged.some((r) => r.gateway) ? kept : tagged;
}

/** routesForGateways with the configured tunnels and the providers' current health. */
export function gatewayRoutes<T extends GatewayRoute>(routes: T[]): (T & { gateway?: string })[] {
  return routesForGateways(routes, getDnsGatewayTunnels(), (ip) => tunnelStateOf(ip).up);
}

/** Every configured gateway with its state (and its provider's), for /dns/health and logs. */
export function gatewayStates(): GatewayState[] {
  const withUrl = new Set(getDnsGatewayTunnels().filter((t) => t.providerUrl).map((t) => t.ip));
  return getDnsGatewayIps().map((ip) => ({ ...stateOf(ip), ...(withUrl.has(ip) ? { tunnel: tunnelStateOf(ip) } : {}) }));
}

/** The fields of a peer certificate this file keeps. Pure. */
export function toGatewayCert(peer: tls.PeerCertificate | undefined): GatewayCert | undefined {
  if (!peer || !peer.valid_to) return undefined;
  const dn = (d: unknown) => {
    const o = (d ?? {}) as Record<string, unknown>;
    return [o.O, o.CN].filter((v) => typeof v === "string" && v).join(", ");
  };
  const names = (peer.subjectaltname || "").split(",").map((s) => s.trim())
    .filter((s) => s.startsWith("DNS:")).map((s) => s.slice(4).toLowerCase());
  const issuer = dn(peer.issuer);
  return {
    notAfter: new Date(peer.valid_to).toISOString(),
    issuer,
    names,
    selfSigned: issuer === dn(peer.subject) && JSON.stringify(peer.issuer) === JSON.stringify(peer.subject),
  };
}

/** One TLS handshake: the error (undefined when it completed) and the certificate seen. */
export function checkGatewayTls(ip: string, port = 443, servername = `gateway.entrypoint.${getServerDomain()}`): Promise<{ error?: string; cert?: GatewayCert }> {
  return new Promise((resolve) => {
    const socket = tls.connect({ host: ip, port, servername, rejectUnauthorized: false, timeout: TIMEOUT_MS });
    const done = (error?: string, cert?: GatewayCert) => {
      socket.destroy();
      resolve({ error, cert });
    };
    socket.once("secureConnect", () => {
      let cert: GatewayCert | undefined;
      try {
        cert = toGatewayCert(socket.getPeerCertificate());
      } catch {
        cert = undefined;
      }
      done(undefined, cert);
    });
    socket.once("timeout", () => done("timeout"));
    socket.once("error", (err) => done(err.message));
  });
}

/** One TLS handshake; resolves with the error, or undefined when it completed. */
export async function checkGateway(ip: string, port = 443, servername = `gateway.entrypoint.${getServerDomain()}`): Promise<string | undefined> {
  return (await checkGatewayTls(ip, port, servername)).error;
}

/**
 * Why a gateway's certificate is a problem for /dns/health, or null: judged only when
 * `minDays` > 0 (DNS_GATEWAY_CERT_MIN_DAYS). It must be a CA's (not the self-signed
 * fallback), name *.<zone>, and stay valid for more than `minDays`. Pure.
 */
export function gatewayCertProblem(cert: GatewayCert | undefined, zone: string, minDays: number, now: Date): string | null {
  if (minDays <= 0 || !cert) return null;
  const wildcard = `*.${zone.toLowerCase()}`;
  if (cert.selfSigned) return `presents a self-signed certificate (${cert.issuer || "no issuer"}), not *.${zone}`;
  if (!cert.names.includes(wildcard)) return `certificate does not name ${wildcard} (${cert.names.join(", ") || "no DNS names"})`;
  const days = (new Date(cert.notAfter).getTime() - now.getTime()) / 86_400_000;
  if (days < minDays) return `certificate ${wildcard} expires ${cert.notAfter} (${Math.floor(days)} days left, renewal expected at 30)`;
  return null;
}

/** GET <url>/api/ping on a tunnel provider (self-signed accepted); the error, or undefined on 200. */
export function checkProvider(url: string): Promise<string | undefined> {
  return new Promise((resolve) => {
    const target = `${url}/api/ping`;
    const client = target.startsWith("https:") ? https : http;
    const req = client.get(target, { timeout: TIMEOUT_MS, rejectUnauthorized: false }, (res) => {
      res.resume();
      resolve(res.statusCode === 200 ? undefined : `status ${res.statusCode}`);
    });
    req.once("timeout", () => req.destroy(new Error("timeout")));
    req.once("error", (err) => resolve(err.message));
  });
}

function answerKey(): string {
  const tunnels = getDnsGatewayTunnels().map((t) => `${t.ip}:${tunnelStateOf(t.ip).up}`);
  return `${healthyGatewayIps().join(",")}|${tunnels.join(",")}`;
}

/** Check every gateway and provider once; true when some answer may have changed. */
export async function checkGateways(): Promise<boolean> {
  const before = answerKey();
  const ips = getDnsGatewayIps();
  const tunnels = getDnsGatewayTunnels().filter((t) => t.providerUrl);
  for (const ip of [...states.keys()]) if (!ips.includes(ip)) states.delete(ip);
  for (const ip of [...tunnelStates.keys()]) if (!tunnels.some((t) => t.ip === ip)) tunnelStates.delete(ip);
  const apply = (map: Map<string, GatewayState>, ip: string, error: string | undefined, what: string, cert?: GatewayCert) => {
    const prev = map.get(ip) ?? { ip, up: true, streak: 0 };
    const next = nextState(prev, !error, error, new Date());
    if (cert) next.cert = cert;
    map.set(ip, next);
    if (next.up !== prev.up) console.log(`[gateways] ${what} ${ip} ${next.up ? "UP" : `DOWN (${error})`}`);
    if (cert && prev.cert?.notAfter !== cert.notAfter) {
      console.log(`[gateways] ${what} ${ip} certificate ${cert.selfSigned ? "self-signed" : cert.names.join(",")}, until ${cert.notAfter}${cert.issuer ? ` (${cert.issuer})` : ""}`);
    }
  };
  await Promise.all([
    ...ips.map(async (ip) => {
      const { error, cert } = await checkGatewayTls(ip);
      apply(states, ip, error, "gateway", cert);
    }),
    ...tunnels.map(async (t) => apply(tunnelStates, t.ip, await checkProvider(t.providerUrl!), "tunnel provider of")),
  ]);
  return answerKey() !== before;
}

let timer: NodeJS.Timeout | null = null;

/** Start checking; `onChange` runs when some answer may have changed (re-sync the zones). */
export function startGatewayHealth(onChange: () => void): void {
  if (timer || getDnsGatewayIps().length < 2) return; // one gateway: nothing to fail over to
  let running = false;
  const tick = async () => {
    if (running) return;
    running = true;
    try {
      if (await checkGateways()) {
        const tunnelsDown = getDnsGatewayTunnels().filter((t) => !tunnelStateOf(t.ip).up).map((t) => t.ip);
        console.log(`[gateways] answering ${healthyGatewayIps().join(",")}`
          + (tunnelsDown.length ? `, NAT boxes not through ${tunnelsDown.join(",")} (provider down)` : ""));
        onChange();
      }
    } catch (e) {
      console.error(`[gateways] check failed: ${(e as Error).message ?? e}`);
    } finally {
      running = false;
    }
  };
  timer = setInterval(tick, INTERVAL_MS);
  tick();
  const providers = getDnsGatewayTunnels().filter((t) => t.providerUrl).map((t) => t.providerUrl);
  console.log(`[gateways] health checks on ${getDnsGatewayIps().join(",")}${providers.length ? ` + providers ${providers.join(",")}` : ""} every ${INTERVAL_MS / 1000}s`);
}

export function stopGatewayHealth(): void {
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
}
