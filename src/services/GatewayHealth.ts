import * as tls from "tls";
import { getDnsGatewayIps, getServerDomain } from "../configuration/config.js";

/**
 * Health of the gateways in DNS_GATEWAY_IPS, so a dead one leaves the gateway answers
 * (mesh-router-nameserver docs/architecture.md §12, "One gateway down").
 *
 * Every INTERVAL_MS each gateway gets one TLS handshake on :443 with SNI
 * gateway.entrypoint.<zone>: a name the gateway always terminates itself (self-signed,
 * not verified), so the check is the same whether the gateway is the edge or sits
 * behind a TCP passthrough. A gateway goes down after FALL failed checks in a row and
 * back up after RISE good ones; every gateway starts up.
 *
 * healthyGatewayIps() is what user zones answer: the healthy gateways, or all of them
 * when none is (a wrong probe must never empty the answer). The full list stays what
 * boxes trust for PROXY headers (/version gatewayIps): a gateway that comes back must
 * not find itself distrusted.
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
}

const states = new Map<string, GatewayState>();

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

function stateOf(ip: string): GatewayState {
  return states.get(ip) ?? { ip, up: true, streak: 0 };
}

/** The gateway IPs user zones should answer right now. */
export function healthyGatewayIps(): string[] {
  return pickHealthy(getDnsGatewayIps(), (ip) => stateOf(ip).up);
}

/** Every configured gateway with its state, for /dns/health and logs. */
export function gatewayStates(): GatewayState[] {
  return getDnsGatewayIps().map(stateOf);
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

/** Check every gateway once; true when the answer set changed. */
export async function checkGateways(): Promise<boolean> {
  const before = healthyGatewayIps().join(",");
  const ips = getDnsGatewayIps();
  for (const ip of [...states.keys()]) if (!ips.includes(ip)) states.delete(ip);
  await Promise.all(ips.map(async (ip) => {
    const error = await checkGateway(ip);
    const prev = stateOf(ip);
    const next = nextState(prev, !error, error, new Date());
    states.set(ip, next);
    if (next.up !== prev.up) {
      console.log(`[gateways] ${ip} ${next.up ? "UP" : `DOWN (${error})`}`);
    }
  }));
  return healthyGatewayIps().join(",") !== before;
}

let timer: NodeJS.Timeout | null = null;

/** Start checking; `onChange` runs when the answer set changed (re-sync the zones). */
export function startGatewayHealth(onChange: () => void): void {
  if (timer || getDnsGatewayIps().length < 2) return; // one gateway: nothing to fail over to
  let running = false;
  const tick = async () => {
    if (running) return;
    running = true;
    try {
      if (await checkGateways()) {
        console.log(`[gateways] answering ${healthyGatewayIps().join(",")}`);
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
  console.log(`[gateways] health checks on ${getDnsGatewayIps().join(",")} every ${INTERVAL_MS / 1000}s`);
}

export function stopGatewayHealth(): void {
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
}
