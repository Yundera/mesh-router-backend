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
 * In memory: one backend, and a restart starts from "all up", the safe side.
 */

const INTERVAL_MS = 15_000;
const TIMEOUT_MS = 5_000;
const FALL = 2;
const RISE = 2;

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

/** Every configured gateway with its state (and its provider's), for /dns/health and logs. */
export function gatewayStates(): GatewayState[] {
  const withUrl = new Set(getDnsGatewayTunnels().filter((t) => t.providerUrl).map((t) => t.ip));
  return getDnsGatewayIps().map((ip) => ({ ...stateOf(ip), ...(withUrl.has(ip) ? { tunnel: tunnelStateOf(ip) } : {}) }));
}

/** One TLS handshake; resolves with the error, or undefined when it completed. */
export function checkGateway(ip: string, port = 443, servername = `gateway.entrypoint.${getServerDomain()}`): Promise<string | undefined> {
  return new Promise((resolve) => {
    const socket = tls.connect({ host: ip, port, servername, rejectUnauthorized: false, timeout: TIMEOUT_MS });
    const done = (error?: string) => {
      socket.destroy();
      resolve(error);
    };
    socket.once("secureConnect", () => done());
    socket.once("timeout", () => done("timeout"));
    socket.once("error", (err) => done(err.message));
  });
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
  const apply = (map: Map<string, GatewayState>, ip: string, error: string | undefined, what: string) => {
    const prev = map.get(ip) ?? { ip, up: true, streak: 0 };
    const next = nextState(prev, !error, error, new Date());
    map.set(ip, next);
    if (next.up !== prev.up) console.log(`[gateways] ${what} ${ip} ${next.up ? "UP" : `DOWN (${error})`}`);
  };
  await Promise.all([
    ...ips.map(async (ip) => apply(states, ip, await checkGateway(ip), "gateway")),
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
