import { Route } from "./Routes.js";
import http from 'http';
import https from 'https';
import { LookupFunction } from 'net';
import { getDnsIpZone } from "../configuration/config.js";
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Route validation timeout in milliseconds.
 * Short timeout to avoid blocking registration.
 */
const VALIDATION_TIMEOUT = 5000;

/**
 * Load mesh-router CA certificate for validating routes using our private CA.
 */
const CA_CERT_PATH = process.env.CA_CERT_PATH || path.join(__dirname, '../../config/ca-cert.pem');
let customCaAgent: https.Agent | undefined;

try {
  if (fs.existsSync(CA_CERT_PATH)) {
    const caCert = fs.readFileSync(CA_CERT_PATH);
    customCaAgent = new https.Agent({ ca: caCert });
    console.log('[RouteValidator] Loaded custom CA cert from', CA_CERT_PATH);
  } else {
    console.warn('[RouteValidator] CA cert not found at', CA_CERT_PATH, '- HTTPS validation will use system CA only');
  }
} catch (err) {
  console.error('[RouteValidator] Failed to load CA cert:', err);
}

/**
 * Result of route validation.
 */
export interface ValidationResult {
  valid: boolean;
  error?: string;
  responseTime?: number;
  url?: string;  // The URL that was tested
}

/**
 * Result of validating multiple routes.
 */
export interface RoutesValidationResult {
  accepted: Array<{ route: Route; responseTime?: number; url?: string }>;
  rejected: Array<{ route: Route; error: string; url?: string }>;
}

/**
 * Validate HTTPS endpoint using https.request.
 * Races system CA and custom CA in parallel — if either succeeds, the route is valid.
 * This handles both publicly-trusted certs and mesh-router CA-signed certs.
 */
function validateWithHttps(
  url: string,
  hostname: string,
  port: number,
  startTime: number,
  lookup?: LookupFunction
): Promise<ValidationResult> {
  const makeRequest = (agent?: https.Agent): Promise<ValidationResult> =>
    new Promise((resolve) => {
      const options: https.RequestOptions = {
        hostname,
        port,
        path: '/',
        method: 'HEAD',
        timeout: VALIDATION_TIMEOUT,
        ...(agent ? { agent } : {}),
        ...(lookup ? { lookup } : {}),
      };

      const req = https.request(options, () => {
        const responseTime = Date.now() - startTime;
        resolve({ valid: true, responseTime, url });
      });

      req.on('error', (err) => {
        resolve(handleHttpError(err, url));
      });

      req.on('timeout', () => {
        req.destroy();
        resolve({ valid: false, error: 'Connection timeout - host unreachable', url });
      });

      req.end();
    });

  // Race system CA and custom CA — first valid wins
  const attempts = [makeRequest()];
  if (customCaAgent) {
    attempts.push(makeRequest(customCaAgent));
  }

  return Promise.all(attempts).then((results) => {
    return results.find((r) => r.valid) || results[0];
  });
}

/**
 * Validate a plain-HTTP endpoint at a fixed address (see pinnedLookup). fetch can't
 * take a custom lookup, so this uses http.request; any response means reachable.
 */
function validateWithHttpPinned(
  url: string,
  hostname: string,
  port: number,
  startTime: number,
  lookup: LookupFunction
): Promise<ValidationResult> {
  return new Promise((resolve) => {
    const req = http.request(
      { hostname, port, path: '/', method: 'HEAD', timeout: VALIDATION_TIMEOUT, lookup },
      () => resolve({ valid: true, responseTime: Date.now() - startTime, url })
    );
    req.on('error', (err) => resolve(handleFetchError(err, url)));
    req.on('timeout', () => {
      req.destroy();
      resolve({ valid: false, error: 'Connection timeout - host unreachable', url });
    });
    req.end();
  });
}

/**
 * A DNS lookup that always answers `ip`. Used for domain routes in our own ip.<zone>
 * (DNS_IP_ZONE): that zone answers only IPs already accepted from an agent, so
 * resolving the name of a new box's route would fail before its first acceptance.
 * The name encodes route.ip; connect there and keep the name for SNI/Host.
 */
function pinnedLookup(ip: string): LookupFunction {
  const family = ip.includes(':') ? 6 : 4;
  return ((_hostname: string, options: { all?: boolean }, callback: (...args: unknown[]) => void) => {
    if (options?.all) {
      callback(null, [{ address: ip, family }]);
    } else {
      callback(null, ip, family);
    }
  }) as LookupFunction;
}

/** True for a domain route inside DNS_IP_ZONE. */
function isOwnIpZoneDomain(route: Route): boolean {
  const zone = getDnsIpZone();
  return !!zone && route.type === 'domain' && !!route.domain
    && route.domain.toLowerCase().replace(/\.$/, '').endsWith(`.${zone}`);
}

/**
 * Handle HTTPS request errors with specific error messages.
 */
function handleHttpError(err: Error, url: string): ValidationResult {
  const errorMessage = err.message;

  if (errorMessage.includes('ECONNREFUSED')) {
    return { valid: false, error: 'Connection refused - port may be blocked', url };
  }
  if (errorMessage.includes('ETIMEDOUT')) {
    return { valid: false, error: 'Connection timeout - host unreachable', url };
  }
  if (errorMessage.includes('ENOTFOUND')) {
    return { valid: false, error: 'DNS resolution failed', url };
  }
  if (errorMessage.includes('certificate') || errorMessage.includes('CERT_') || errorMessage.includes('SSL')) {
    return { valid: false, error: `SSL certificate invalid: ${errorMessage}`, url };
  }
  if (errorMessage.includes('EHOSTUNREACH')) {
    return { valid: false, error: 'Host unreachable', url };
  }

  return { valid: false, error: errorMessage, url };
}

/**
 * Handle fetch errors (for HTTP requests).
 */
function handleFetchError(err: unknown, url: string): ValidationResult {
  const errorMessage = err instanceof Error ? err.message : String(err);

  if (errorMessage.includes('ECONNREFUSED')) {
    return { valid: false, error: 'Connection refused - port may be blocked', url };
  }
  if (errorMessage.includes('ETIMEDOUT') || errorMessage.includes('aborted')) {
    return { valid: false, error: 'Connection timeout - host unreachable', url };
  }
  if (errorMessage.includes('ENOTFOUND')) {
    return { valid: false, error: 'DNS resolution failed', url };
  }

  return { valid: false, error: errorMessage, url };
}

/**
 * Validate a single route by testing connectivity.
 * All routes (both IP and domain types) are validated.
 *
 * For HTTPS routes, races system CA and custom CA — accepts if either succeeds.
 *
 * @param route - The route to validate
 * @returns ValidationResult indicating if the route is reachable
 */
export async function validateRoute(route: Route): Promise<ValidationResult> {
  // For domain routes, require domain field
  if (route.type === 'domain' && !route.domain) {
    return { valid: false, error: 'Domain is required for domain routes', url: 'N/A' };
  }

  // Determine target host: use domain for domain routes, IP for IP routes
  const targetHost = route.type === 'domain' && route.domain
    ? route.domain
    : route.ip;

  const startTime = Date.now();
  // Use targetScheme for backend connection, fallback to ingress scheme
  const targetScheme = route.targetScheme || route.scheme || 'https';
  // Wrap IPv6 addresses in brackets for valid URL format
  const hostForUrl = targetHost.includes(':') ? `[${targetHost}]` : targetHost;
  const url = `${targetScheme}://${hostForUrl}:${route.port}/`;

  const lookup = isOwnIpZoneDomain(route) ? pinnedLookup(route.ip) : undefined;

  if (targetScheme === 'https') {
    return validateWithHttps(url, targetHost, route.port, startTime, lookup);
  }

  if (lookup) {
    return validateWithHttpPinned(url, targetHost, route.port, startTime, lookup);
  }

  // HTTP validation using fetch (don't follow redirects — a 3xx still means the route is reachable)
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), VALIDATION_TIMEOUT);

    await fetch(url, {
      method: 'HEAD',
      signal: controller.signal,
      redirect: 'manual',
    });

    clearTimeout(timeoutId);

    const responseTime = Date.now() - startTime;
    return { valid: true, responseTime, url };
  } catch (err) {
    return handleFetchError(err, url);
  }
}

/**
 * Validate multiple routes and return accepted/rejected arrays.
 * All routes are validated for connectivity.
 *
 * @param routes - Array of routes to validate
 * @returns Object containing accepted routes and rejected routes with errors
 */
export async function validateRoutes(routes: Route[]): Promise<RoutesValidationResult> {
  const accepted: Array<{ route: Route; responseTime?: number; url?: string }> = [];
  const rejected: Array<{ route: Route; error: string; url?: string }> = [];

  // Validate routes in parallel for efficiency
  const validationPromises = routes.map(async (route) => {
    const result = await validateRoute(route);
    return { route, result };
  });

  const results = await Promise.all(validationPromises);

  for (const { route, result } of results) {
    if (result.valid) {
      accepted.push({ route, responseTime: result.responseTime, url: result.url });
    } else {
      rejected.push({ route, error: result.error || 'Unknown validation error', url: result.url });
    }
  }

  return { accepted, rejected };
}
