import { createHash, randomBytes } from "node:crypto";
import { getFirestore, FieldValue } from "firebase-admin/firestore";
import { NSL_ROUTER_COLLECTION, NSLRouterData, NSLRouterMail } from "../DataBaseDTO/DataBaseNSLRouter.js";
import { getSendgridApiKey } from "../configuration/config.js";
import { getRedisClient } from "../redis/redisClient.js";
import { getDomain } from "./Domain.js";

/**
 * Per-user mail forwarding, phase 1 of doc/USER_MAIL.md: mail to `<user>@<zone>` (also
 * `<user>+tag@` and `<app>.<user>@`) is forwarded to one external address the user chose
 * from their box and confirmed by clicking a link sent there. The setting lives on the
 * user's nsl-router document (`mail`); InboundMail.ts does the forwarding.
 *
 * The confirmation exists so a user cannot point the forward at a stranger and mail-bomb
 * them through us. The link opens a page with a button (POST): mail scanners that prefetch
 * GET links must not confirm on the owner's behalf.
 */

const CONFIRM_TTL_MS = 48 * 60 * 60 * 1000;
/** Confirmation mails per user per day: each one goes to an address nobody has confirmed yet. */
const CONFIRM_MAILS_PER_DAY = 5;
const DAY_SECONDS = 24 * 60 * 60;

export type ForwardState = "off" | "pending" | "active" | "paused";

/** What the box shows: never the confirmation token. */
export interface ForwardView {
  enabled: boolean;     // inbound mail is configured on this backend
  address: string;      // <user>@<zone>
  state: ForwardState;
  target?: string;
  reason?: string;      // why `paused`
}

export class UserMailError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

/**
 * The user label a local part addresses: `alice`, `alice+tag` and `<app>.alice` are all
 * alice. Undefined for anything else (more dots, bad labels).
 */
export function userLabel(local: string): string | undefined {
  const parts = local.toLowerCase().split("+")[0].split(".");
  if (parts.length > 2 || (parts.length === 2 && !/^[a-z0-9-]{1,20}$/.test(parts[0]))) {
    return undefined;
  }
  const label = parts[parts.length - 1];
  return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(label) ? label : undefined;
}

/** A forward target: a plain address, never in the zone or below it (it would loop). */
export function checkForwardTarget(target: unknown, zone: string): string {
  const addr = typeof target === "string" ? target.trim().toLowerCase() : "";
  if (addr.length > 254 || !/^[a-z0-9._%+-]+@[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(addr)) {
    throw new UserMailError(400, "Enter a valid email address.");
  }
  const domain = addr.split("@")[1];
  const z = zone.toLowerCase();
  if (domain === z || domain.endsWith(`.${z}`)) {
    throw new UserMailError(400, `The forwarding address cannot be in ${zone}.`);
  }
  return addr;
}

export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/** The box's view of a stored setting. `paused` needs SendGrid, so it is passed in. */
export function forwardView(mail: NSLRouterMail | undefined, address: string, enabled: boolean, paused?: string): ForwardView {
  if (!mail?.target) {
    return { enabled, address, state: "off" };
  }
  if (mail.state !== "active") {
    return { enabled, address, state: "pending", target: mail.target };
  }
  return paused
    ? { enabled, address, state: "paused", target: mail.target, reason: paused }
    : { enabled, address, state: "active", target: mail.target };
}

// ---- storage -----------------------------------------------------------------

function userDoc(uid: string) {
  return getFirestore().collection(NSL_ROUTER_COLLECTION).doc(uid);
}

/** The active forward target of a user label, for InboundMail. */
export async function findForward(label: string): Promise<{ uid: string; target: string } | undefined> {
  const found = await getDomain(label).catch(() => null);
  const mail = found?.domain?.mail;
  return found && mail?.state === "active" && mail.target ? { uid: found.uid, target: mail.target } : undefined;
}

/**
 * Sets a new forward target: pending until the link sent to it is clicked. Setting the
 * target that is already active changes nothing, unless SendGrid suppressed it (paused):
 * then it is re-confirmed, which is how the owner resumes.
 */
export async function setForward(uid: string, user: NSLRouterData, rawTarget: unknown, zone: string, confirmBase: string): Promise<NSLRouterMail> {
  const target = checkForwardTarget(rawTarget, zone);
  const current = user.mail;
  if (current?.target === target && current.state === "active" && !(await suppressionReason(target))) {
    return current;
  }
  const sent = await getRedisClient().incr(`mail:confirm:${uid}`);
  if (sent === 1) {
    await getRedisClient().expire(`mail:confirm:${uid}`, DAY_SECONDS);
  }
  if (sent > CONFIRM_MAILS_PER_DAY) {
    throw new UserMailError(429, `At most ${CONFIRM_MAILS_PER_DAY} confirmation emails per day. Try again tomorrow.`);
  }

  // A target SendGrid suppressed (earlier bounce, block, spam report) would swallow the
  // confirmation itself: the owner asking again is the consent to lift it.
  await clearSuppressions(target);

  const token = randomBytes(24).toString("hex");
  const mail: NSLRouterMail = {
    target,
    state: "pending",
    confirmHash: hashToken(token),
    confirmExpires: new Date(Date.now() + CONFIRM_TTL_MS).toISOString(),
    updatedAt: new Date().toISOString(),
  };
  await userDoc(uid).set({ mail }, { merge: true });
  const address = `${user.domainName}@${zone}`;
  await sendConfirmation(target, address, `${confirmBase}/email/confirm/${token}`);
  console.log(`[MAIL FWD] ${user.domainName}: confirmation sent to @${target.split("@")[1]}`);
  return mail;
}

export async function clearForward(uid: string): Promise<void> {
  await userDoc(uid).update({ mail: FieldValue.delete() });
}

/** Activates the forward whose confirmation token this is. Returns the address, or undefined. */
export async function confirmForward(token: string): Promise<{ address: string; target: string } | undefined> {
  if (!/^[0-9a-f]{48}$/.test(token)) {
    return undefined;
  }
  const snap = await getFirestore().collection(NSL_ROUTER_COLLECTION)
    .where("mail.confirmHash", "==", hashToken(token)).limit(1).get();
  const doc = snap.docs[0];
  const data = doc?.data() as NSLRouterData | undefined;
  const mail = data?.mail;
  if (!doc || !mail?.target || !mail.confirmExpires || Date.parse(mail.confirmExpires) < Date.now()) {
    return undefined;
  }
  await doc.ref.update({
    "mail.state": "active",
    "mail.confirmHash": FieldValue.delete(),
    "mail.confirmExpires": FieldValue.delete(),
    "mail.updatedAt": new Date().toISOString(),
  });
  console.log(`[MAIL FWD] ${data.domainName}: forwarding confirmed`);
  return { address: data.domainName, target: mail.target };
}

/** Forwards per user per day; over it, the user's mail is dropped until the next day. */
export async function allowForward(uid: string, perDay: number): Promise<boolean> {
  const key = `mail:fwd:${uid}:${new Date().toISOString().slice(0, 10)}`;
  const count = await getRedisClient().incr(key);
  if (count === 1) {
    await getRedisClient().expire(key, 2 * DAY_SECONDS);
  }
  return count <= perDay;
}

// ---- SendGrid ------------------------------------------------------------------

const SUPPRESSION_LISTS = ["bounces", "blocks", "spam_reports", "invalid_emails"] as const;
const SUPPRESSION_REASON: Record<(typeof SUPPRESSION_LISTS)[number], string> = {
  bounces: "the address bounced",
  blocks: "the receiving server blocked our mail",
  spam_reports: "a forwarded message was reported as spam",
  invalid_emails: "the address does not exist",
};

async function sendgrid(method: string, path: string, body?: unknown): Promise<Response | undefined> {
  const apiKey = getSendgridApiKey();
  if (!apiKey) {
    return undefined;
  }
  return fetch(`https://api.sendgrid.com/v3${path}`, {
    method,
    headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
}

/**
 * Why SendGrid drops mail to this address, if it does. Best effort: an API key without
 * suppression access, or SendGrid unreachable, reads as "not suppressed".
 */
export async function suppressionReason(target: string): Promise<string | undefined> {
  for (const list of SUPPRESSION_LISTS) {
    try {
      const resp = await sendgrid("GET", `/suppression/${list}/${encodeURIComponent(target)}`);
      if (!resp?.ok) {
        continue;
      }
      const entries = await resp.json().catch(() => []);
      if (Array.isArray(entries) && entries.length > 0) {
        return SUPPRESSION_REASON[list];
      }
    } catch {
      // best effort
    }
  }
  return undefined;
}

async function clearSuppressions(target: string): Promise<void> {
  for (const list of SUPPRESSION_LISTS) {
    await sendgrid("DELETE", `/suppression/${list}/${encodeURIComponent(target)}`).catch(() => undefined);
  }
}

async function sendConfirmation(target: string, address: string, link: string): Promise<void> {
  const text = [
    `Someone asked to forward the mail of ${address} to this address.`,
    ``,
    `If it was you, confirm here (the link is valid for 48 hours):`,
    link,
    ``,
    `If it was not you, ignore this message: nothing will be forwarded.`,
  ].join("\n");
  const resp = await sendgrid("POST", "/mail/send", {
    personalizations: [{ to: [{ email: target }] }],
    from: { email: address, name: address },
    subject: `Confirm forwarding of ${address}`,
    content: [{ type: "text/plain", value: text }],
    // The link carries the token: it must not be rewritten into a tracking redirect.
    tracking_settings: { click_tracking: { enable: false, enable_text: false } },
  });
  if (!resp) {
    console.log(`[MAIL FWD] SENDGRID_API_KEY not set: confirmation link for ${address}: ${link}`);
    return;
  }
  if (resp.status !== 202) {
    const detail = await resp.text().catch(() => "");
    console.error(`[MAIL FWD] confirmation mail refused (${resp.status}): ${detail.slice(0, 300)}`);
    throw new UserMailError(502, "The confirmation email could not be sent. Try again later.");
  }
}

// ---- confirmation page --------------------------------------------------------------

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

/** A minimal standalone page for the confirmation link (no assets, no script). */
export function confirmPage(title: string, message: string, button?: { action: string; label: string }): string {
  const form = button
    ? `<form method="post" action="${escapeHtml(button.action)}"><button type="submit">${escapeHtml(button.label)}</button></form>`
    : "";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;color:#222;background:#fff}
button{font:inherit;padding:.6rem 1.2rem;border:0;border-radius:.4rem;background:#2563eb;color:#fff;cursor:pointer}</style></head>
<body><h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p>${form}</body></html>`;
}
