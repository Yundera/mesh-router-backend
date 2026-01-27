// Authentication middleware
import admin from "firebase-admin";
import type { Request, Response, NextFunction } from "express";

export interface AuthUserRequest extends Request {
  user?: {
    uid: string;
  };
}

/**
 * Logs authentication failures with relevant context for security monitoring.
 */
function logAuthFailure(req: Request, reason: string, context: Record<string, unknown> = {}): void {
  const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';
  const userAgent = req.get('User-Agent') || 'unknown';

  console.warn('AUTH_FAILURE', {
    reason,
    clientIp,
    userAgent,
    method: req.method,
    path: req.path,
    ...context,
  });
}

/**
 * Combined authentication middleware that supports:
 * 1. SERVICE_API_KEY authentication (for service-to-service calls)
 *    Format: Bearer SERVICE_API_KEY;uid
 * 2. Firebase authentication (for end-user calls)
 *    Format: Bearer <firebase-id-token>
 */
export const authenticate = async (
  req: AuthUserRequest,
  res: Response,
  next: NextFunction
): Promise<void | Response> => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      logAuthFailure(req, 'missing_auth_header');
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Check for SERVICE_API_KEY authentication
    const serviceApiKey = process.env.SERVICE_API_KEY;
    if (serviceApiKey && authHeader.startsWith(`Bearer ${serviceApiKey};`)) {
      const token = authHeader.split("Bearer ")[1];
      const uid = token.split(";")[1];
      if (!uid) {
        logAuthFailure(req, 'missing_uid_in_service_token');
        return res.status(401).json({ error: "Unauthorized: Missing uid in service token" });
      }
      req.user = { uid };
      return next();
    }

    // Fall back to Firebase authentication
    const idToken = authHeader.split("Bearer ")[1];

    try {
      const decodedToken = await admin.auth().verifyIdToken(idToken);
      req.user = { uid: decodedToken.uid };
      next();
    } catch (firebaseError) {
      logAuthFailure(req, 'firebase_token_invalid', {
        error: firebaseError instanceof Error ? firebaseError.message : String(firebaseError)
      });
      return res.status(401).json({ error: "Unauthorized" });
    }
  } catch (error) {
    logAuthFailure(req, 'auth_middleware_error', {
      error: error instanceof Error ? error.message : String(error)
    });
    return res.status(401).json({ error: "Unauthorized" });
  }
};
