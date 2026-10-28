import tls from "tls";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { getRedisClient } from "../redis/redisClient.js";

/**
 * Probe behind the nameserver's answer rule (mesh-router-nameserver architecture §5):
 * can the box serve <label>.<zone> and *.<label>.<zone> itself, with a certificate a
 * browser trusts? Checked from the backend, never taken from the box's own report.
 *
 * A box with no public IP (behind NAT) is probed through a gateway instead: the gateway
 * passes dot names and the user apex through raw to the box over its tunnel
 * (phase-1.1-gateway-tls.md §3), so the handshake still reaches the box's own
 * certificate. Such a probe only reports; the answer rule needs a public IP to answer
 * the box directly.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CA_CERT_PATH = process.env.CA_CERT_PATH || path.join(__dirname, "../../config/ca-cert.pem");

const PROBE_TIMEOUT_MS = 5000;
/** A certificate expiring sooner than this does not count as trusted. */
const NOT_AFTER_MARGIN_MS = 7 * 24 * 60 * 60 * 1000;
/** Probe state lifetime: an older or missing state means "not direct". */
const STATE_TTL_SECONDS = 60 * 60;

export type CertState = "trusted" | "mesh-ca" | "none";

export interface DnsProbeState {
  publicIp: string | null;
  // how the box was reached: its public IP, or a gateway's passthrough (no public IP)
  via?: "direct" | "gateway";
  cert: CertState;
  issuer?: string;
  notAfter?: string;
  // the TLS handshake completed on both names
  probeOk: boolean;
  reason: string;
  // ISO time of the probe
  at: string;
}

export interface ProbeOptions {
  port?: number;
  // CAs a browser trusts; default Node's bundled roots. Tests inject their own.
  trustedCa?: (string | Buffer)[];
  // the mesh CA, recognised only to report `mesh-ca`; default CA_CERT_PATH if present
  meshCa?: (string | Buffer)[];
  // probe through this gateway when the box has no public IP
  gatewayIp?: string | null;
  now?: number;
}

function defaultMeshCa(): (string | Buffer)[] | undefined {
  try {
    return fs.existsSync(CA_CERT_PATH) ? [fs.readFileSync(CA_CERT_PATH)] : undefined;
  } catch {
    return undefined;
  }
}

interface Handshake {
  ok: boolean;          // chain and name verified against `ca`
  connected: boolean;   // the TLS handshake itself completed
  error?: string;
  issuer?: string;
  notAfter?: Date;
}

/** One TLS handshake to ip:port with SNI `servername`, verified against `ca`. */
function handshake(ip: string, port: number, servername: string, ca?: (string | Buffer)[]): Promise<Handshake> {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: ip,
      port,
      servername,
      ca,
      rejectUnauthorized: false,
      timeout: PROBE_TIMEOUT_MS,
    });
    const done = (result: Handshake) => {
      socket.destroy();
      resolve(result);
    };
    socket.once("secureConnect", () => {
      const peer = socket.getPeerCertificate();
      const issuer = peer?.issuer ? [peer.issuer.O, peer.issuer.CN].filter(Boolean).join(" / ") : undefined;
      const notAfter = peer?.valid_to ? new Date(peer.valid_to) : undefined;
      if (!socket.authorized) {
        done({ ok: false, connected: true, error: String(socket.authorizationError), issuer, notAfter });
        return;
      }
      const nameError = tls.checkServerIdentity(servername, peer);
      done({ ok: !nameError, connected: true, error: nameError?.message, issuer, notAfter });
    });
    socket.once("timeout", () => done({ ok: false, connected: false, error: "timeout" }));
    socket.once("error", (err) => done({ ok: false, connected: false, error: err.message }));
  });
}

/**
 * Probe a box: handshakes on <label>.<zone> and mesh-probe.<label>.<zone> (the wildcard).
 * trusted = both verified by a browser-trusted CA, valid for at least NOT_AFTER_MARGIN.
 */
export async function probeBox(fqdn: string, publicIp: string | null, options: ProbeOptions = {}): Promise<DnsProbeState> {
  const at = new Date(options.now ?? Date.now()).toISOString();
  const target = publicIp ?? options.gatewayIp ?? null;
  if (!target) {
    return { publicIp: null, cert: "none", probeOk: false, reason: "no public IP (no agent route)", at };
  }
  const via: DnsProbeState["via"] = publicIp ? "direct" : "gateway";
  const where = publicIp ? `${target}` : `gateway ${target}`;
  const port = options.port ?? 443;
  const names = [fqdn, `mesh-probe.${fqdn}`];
  const results = await Promise.all(names.map((name) => handshake(target, port, name, options.trustedCa)));
  const probeOk = results.every((r) => r.connected);
  const first = results[0];

  const failed = results.findIndex((r) => !r.ok);
  if (failed === -1) {
    const notAfter = results.map((r) => r.notAfter).filter((d): d is Date => !!d)
      .sort((a, b) => a.getTime() - b.getTime())[0];
    const now = options.now ?? Date.now();
    if (!notAfter || notAfter.getTime() - now < NOT_AFTER_MARGIN_MS) {
      return {
        publicIp, via, cert: "none", issuer: first.issuer, notAfter: notAfter?.toISOString(), probeOk,
        reason: `certificate expires ${notAfter?.toISOString() ?? "at an unknown date"}, within the 7-day margin`, at,
      };
    }
    return {
      publicIp, via, cert: "trusted", issuer: first.issuer, notAfter: notAfter.toISOString(), probeOk,
      reason: `trusted certificate for ${fqdn} and *.${fqdn} on ${where}:${port}`, at,
    };
  }

  // Not browser-trusted: tell a mesh CA certificate apart from anything else.
  const meshCa = options.meshCa ?? defaultMeshCa();
  const failure = results[failed];
  const reason = failure.connected
    ? `${names[failed]}: ${failure.error}`
    : `${where}:${port} unreachable (${failure.error})`;
  if (meshCa && failure.connected) {
    const mesh = await handshake(target, port, names[failed], meshCa);
    if (mesh.ok) {
      return {
        publicIp, via, cert: "mesh-ca", issuer: mesh.issuer, notAfter: mesh.notAfter?.toISOString(), probeOk,
        reason: `${names[failed]}: mesh CA certificate (not browser-trusted)`, at,
      };
    }
  }
  return {
    publicIp, via, cert: "none", issuer: failure.issuer, notAfter: failure.notAfter?.toISOString(), probeOk, reason, at,
  };
}

function stateKey(userId: string): string {
  return `dns:state:${userId}`;
}

export async function saveProbeState(userId: string, state: DnsProbeState): Promise<void> {
  await getRedisClient().setex(stateKey(userId), STATE_TTL_SECONDS, JSON.stringify(state));
}

/** The last probe within STATE_TTL, or null. */
export async function getProbeState(userId: string): Promise<DnsProbeState | null> {
  const raw = await getRedisClient().get(stateKey(userId));
  if (!raw) return null;
  try {
    return JSON.parse(raw) as DnsProbeState;
  } catch {
    return null;
  }
}

/** True when the user has no probe younger than `minAgeMs`. */
export function probeDue(state: DnsProbeState | null, minAgeMs: number, now = Date.now()): boolean {
  return !state || now - new Date(state.at).getTime() >= minAgeMs;
}
