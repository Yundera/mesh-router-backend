import { execFile } from 'child_process';
import { isIPv4, isIPv6 } from 'net';

const PROBE_TIMEOUT_SECONDS = 2;
const MAX_CANDIDATES_PER_REQUEST = 4;
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQUESTS = 10;

export type IpFamily = 'ipv4' | 'ipv6';

export interface ProbeResult {
  ip: string;
  family: IpFamily;
  reachable: boolean;
  reason?: string;
}

/**
 * Returns true if `ip` is in a range that should never be probed
 * (RFC1918 private, loopback, link-local, CGNAT, multicast, ULA, etc.).
 *
 * Pre-filtering these saves probe calls and prevents callers from
 * weaponizing the endpoint to scan internal infrastructure of the host
 * running mesh-router-backend.
 */
export function isLanOrReserved(ip: string): boolean {
  if (isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    const [a, b] = parts;
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a >= 224) return true;
    if (a === 0) return true;
    return false;
  }

  if (isIPv6(ip)) {
    const lower = ip.toLowerCase();
    if (lower === '::1' || lower === '::') return true;
    if (lower.startsWith('fe8') || lower.startsWith('fe9') ||
        lower.startsWith('fea') || lower.startsWith('feb')) return true;
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
    if (lower.startsWith('ff')) return true;
    if (lower.startsWith('2001:db8')) return true;
    return false;
  }

  return true;
}

function detectFamily(ip: string): IpFamily | null {
  if (isIPv4(ip)) return 'ipv4';
  if (isIPv6(ip)) return 'ipv6';
  return null;
}

async function pingOnce(ip: string, family: IpFamily): Promise<{ reachable: boolean; reason?: string }> {
  const familyFlag = family === 'ipv4' ? '-4' : '-6';
  const args = [familyFlag, '-c', '1', '-W', String(PROBE_TIMEOUT_SECONDS), ip];

  return new Promise((resolve) => {
    execFile('ping', args, { timeout: (PROBE_TIMEOUT_SECONDS + 1) * 1000 }, (err) => {
      if (!err) {
        resolve({ reachable: true });
        return;
      }
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'ENOENT') {
        resolve({ reachable: false, reason: 'ping binary not available on backend host' });
        return;
      }
      resolve({ reachable: false, reason: 'no ICMP echo reply within timeout' });
    });
  });
}

export async function probeCandidates(rawCandidates: string[]): Promise<ProbeResult[]> {
  const candidates = rawCandidates.slice(0, MAX_CANDIDATES_PER_REQUEST);
  const probes = candidates.map(async (ip): Promise<ProbeResult> => {
    const family = detectFamily(ip);
    if (!family) {
      return { ip, family: 'ipv4', reachable: false, reason: 'not a valid IP address' };
    }
    if (isLanOrReserved(ip)) {
      return { ip, family, reachable: false, reason: 'IP is in a reserved/private range' };
    }
    const { reachable, reason } = await pingOnce(ip, family);
    return { ip, family, reachable, reason };
  });
  return Promise.all(probes);
}

const rateLimitState = new Map<string, { count: number; windowStart: number }>();

export function checkRateLimit(clientIp: string): { allowed: boolean; retryAfterSeconds?: number } {
  const now = Date.now();
  const state = rateLimitState.get(clientIp);
  if (!state || now - state.windowStart > RATE_LIMIT_WINDOW_MS) {
    rateLimitState.set(clientIp, { count: 1, windowStart: now });
    return { allowed: true };
  }
  if (state.count >= RATE_LIMIT_MAX_REQUESTS) {
    const retryAfterSeconds = Math.ceil((RATE_LIMIT_WINDOW_MS - (now - state.windowStart)) / 1000);
    return { allowed: false, retryAfterSeconds };
  }
  state.count += 1;
  return { allowed: true };
}

export const PROBE_LIMITS = {
  MAX_CANDIDATES_PER_REQUEST,
  RATE_LIMIT_MAX_REQUESTS,
  RATE_LIMIT_WINDOW_MS,
};
