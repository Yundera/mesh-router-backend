import { Route } from "./Routes.js";

/**
 * Route validation timeout in milliseconds.
 * Short timeout to avoid blocking registration.
 */
const VALIDATION_TIMEOUT = 5000;

/**
 * Result of route validation.
 */
export interface ValidationResult {
  valid: boolean;
  error?: string;
  responseTime?: number;
}

/**
 * Result of validating multiple routes.
 */
export interface RoutesValidationResult {
  accepted: Route[];
  rejected: Array<{ route: Route; error: string }>;
}

/**
 * Validate a single route by testing connectivity.
 * All routes (both IP and domain types) are validated.
 *
 * @param route - The route to validate
 * @returns ValidationResult indicating if the route is reachable
 */
export async function validateRoute(route: Route): Promise<ValidationResult> {
  // For domain routes, require domain field
  if (route.type === 'domain' && !route.domain) {
    return { valid: false, error: 'Domain is required for domain routes' };
  }

  // Determine target host: use domain for domain routes, IP for IP routes
  const targetHost = route.type === 'domain' && route.domain
    ? route.domain
    : route.ip;

  const startTime = Date.now();
  const scheme = route.scheme || 'https';
  const url = `${scheme}://${targetHost}:${route.port}/`;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), VALIDATION_TIMEOUT);

    const response = await fetch(url, {
      method: 'HEAD',
      signal: controller.signal,
      // Ignore SSL certificate errors for self-signed certs
      // Node.js: set NODE_TLS_REJECT_UNAUTHORIZED=0 or use custom agent
    });

    clearTimeout(timeoutId);

    const responseTime = Date.now() - startTime;

    // Any response (even 4xx) means the route is reachable
    // We're testing connectivity, not the application
    return {
      valid: true,
      responseTime,
    };
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : String(err);

    // Check for specific error types
    if (errorMessage.includes('ECONNREFUSED')) {
      return { valid: false, error: 'Connection refused - port may be blocked' };
    }
    if (errorMessage.includes('ETIMEDOUT') || errorMessage.includes('aborted')) {
      return { valid: false, error: 'Connection timeout - host unreachable' };
    }
    if (errorMessage.includes('ENOTFOUND')) {
      return { valid: false, error: 'DNS resolution failed' };
    }
    if (errorMessage.includes('certificate')) {
      // SSL errors still mean the host is reachable
      return {
        valid: true,
        responseTime: Date.now() - startTime,
      };
    }

    return { valid: false, error: errorMessage };
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
  const accepted: Route[] = [];
  const rejected: Array<{ route: Route; error: string }> = [];

  // Validate routes in parallel for efficiency
  const validationPromises = routes.map(async (route) => {
    const result = await validateRoute(route);
    return { route, result };
  });

  const results = await Promise.all(validationPromises);

  for (const { route, result } of results) {
    if (result.valid) {
      accepted.push(route);
    } else {
      rejected.push({ route, error: result.error || 'Unknown validation error' });
    }
  }

  return { accepted, rejected };
}
