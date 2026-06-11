import { verifySignature } from "../library/KeyLib.js";
import { getUserDomain } from "./Domain.js";
import { getServerDomain, getSendgridApiKey } from "../configuration/config.js";

/**
 * Per-user transactional mail relay.
 *
 * Apps on a PCS (Vaultwarden, Nextcloud, ...) send SMTP to the local mail-gateway,
 * which forwards each email here as POST /email/send. This module enforces two things:
 *
 *   1. Identity is established at the *verification step*, not trusted from input.
 *      The credential is "<userid>:<signature>" (the PCS provider string's identity),
 *      and the userid is only trusted after the Ed25519 signature is verified against
 *      the public key stored for that user — the same primitive used for route
 *      registration (POST /routes/:userid/:sig).
 *
 *   2. The From address is *derived from the verified identity*, never from the caller.
 *      It is always <app>.<user-domain>@<server-domain> (e.g. vaultwarden.john@nsl.sh),
 *      which makes impersonation between users structurally impossible: the domain part
 *      comes from the signature-verified identity, and the caller only influences the
 *      sanitized app prefix.
 */

// In-memory per-user rate limit. Intentionally simple (single-instance); good enough
// for now. Resets on restart and is not shared across instances.
const RATE_LIMIT_MAX = 100; // emails per hour per user
const RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000;
const rateLimitMap = new Map<string, { count: number; resetTime: number }>();

export interface EmailAttachment {
  filename: string;
  content: string; // base64 encoded
  type: string; // MIME type
  content_id?: string; // for inline images (cid: references)
}

export interface EmailSendRequest {
  to: string;
  subject: string;
  text: string;
  html?: string;
  appName: string; // e.g. "vaultwarden", "nextcloud"; derived by the gateway from the SMTP sender
  attachments?: EmailAttachment[];
}

/** A cryptographically verified caller identity. Only constructed by verifyEmailCredential. */
export interface EmailIdentity {
  userid: string;
  domainName: string;
}

/** Carries an HTTP status so the route handler can map failures without leaking internals. */
export class EmailError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = "EmailError";
  }
}

/**
 * Verify a "<userid>:<signature>" relay credential and return the trusted identity.
 *
 * The userid is NEVER trusted on its own — it is only returned after the signature is
 * verified against the public key stored for that user. Throws EmailError on any failure.
 */
export async function verifyEmailCredential(credential: string): Promise<EmailIdentity> {
  const sep = credential.indexOf(":");
  if (sep <= 0 || sep === credential.length - 1) {
    throw new EmailError(401, "Malformed credential. Expected '<userid>:<signature>'.");
  }
  const userid = credential.slice(0, sep);
  const signature = credential.slice(sep + 1);

  const userData = await getUserDomain(userid);
  if (!userData || !userData.domainName) {
    // Same response whether the user is unknown or has no domain — don't leak which.
    throw new EmailError(401, "Unknown user or no domain registered.");
  }

  let isValid = false;
  try {
    isValid = await verifySignature(userData.publicKey, signature, userid);
  } catch {
    // Invalid signature format (e.g. non-base36 characters).
    throw new EmailError(401, "Invalid signature.");
  }
  if (!isValid) {
    throw new EmailError(401, "Invalid signature.");
  }

  return { userid, domainName: userData.domainName };
}

/** Lowercase, strip to [a-z0-9-], cap at 20 chars; never empty. Prevents header injection. */
function sanitizeAppName(appName: string): string {
  return appName.toLowerCase().replace(/[^a-z0-9-]/g, "").substring(0, 20) || "app";
}

function checkRateLimit(userid: string): boolean {
  const now = Date.now();
  const entry = rateLimitMap.get(userid);
  if (!entry || now > entry.resetTime) {
    rateLimitMap.set(userid, { count: 1, resetTime: now + RATE_LIMIT_WINDOW_MS });
    return true;
  }
  if (entry.count >= RATE_LIMIT_MAX) {
    return false;
  }
  entry.count++;
  return true;
}

/**
 * Enforced sender: <app>.<user-domain>@<server-domain>, e.g. vaultwarden.john@nsl.sh.
 * domainName comes from the verified identity; the caller cannot influence it.
 */
function buildSender(identity: EmailIdentity, appName: string): string {
  return `${sanitizeAppName(appName)}.${identity.domainName}@${getServerDomain()}`;
}

/**
 * Rate-limit, derive the enforced sender, and send via SendGrid for a verified identity.
 *
 * If SENDGRID_API_KEY is unset the send is skipped (logged) and reported as success, so
 * deployments without mail configured — and local dev — don't fail. Returns the resolved
 * From address and whether the send was skipped.
 */
export async function sendUserEmail(
  identity: EmailIdentity,
  req: EmailSendRequest,
): Promise<{ from: string; skipped: boolean }> {
  if (!checkRateLimit(identity.userid)) {
    throw new EmailError(429, "Rate limit exceeded. Maximum 100 emails per hour.");
  }

  const from = buildSender(identity, req.appName);
  const apiKey = getSendgridApiKey();

  if (!apiKey) {
    console.log(`[EMAIL SKIPPED] SENDGRID_API_KEY not set. from=${from} to=${req.to} subject="${req.subject}"`);
    return { from, skipped: true };
  }

  // SendGrid v3 requires content entries in increasing precedence: text/plain before text/html.
  const content: Array<{ type: string; value: string }> = [{ type: "text/plain", value: req.text }];
  if (req.html) {
    content.push({ type: "text/html", value: req.html });
  }

  const payload: Record<string, unknown> = {
    personalizations: [{ to: [{ email: req.to }] }],
    from: { email: from },
    subject: req.subject,
    content,
  };

  if (req.attachments && req.attachments.length > 0) {
    payload.attachments = req.attachments.map((a) => ({
      filename: a.filename,
      content: a.content,
      type: a.type,
      disposition: a.content_id ? "inline" : "attachment",
      ...(a.content_id ? { content_id: a.content_id } : {}),
    }));
  }

  const resp = await fetch("https://api.sendgrid.com/v3/mail/send", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  // SendGrid returns 202 Accepted on success.
  if (resp.status !== 202) {
    const detail = await resp.text().catch(() => "");
    throw new EmailError(502, `SendGrid rejected the email (status ${resp.status}): ${detail}`);
  }

  console.log(`Email sent from ${from} to ${req.to}`);
  return { from, skipped: false };
}
