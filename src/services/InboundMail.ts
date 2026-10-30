import { createHash, timingSafeEqual } from "node:crypto";
import { simpleParser, ParsedMail, AddressObject, EmailAddress } from "mailparser";
import { getSendgridApiKey } from "../configuration/config.js";
import { getRedisClient } from "../redis/redisClient.js";
import { allowForward, findForward, userLabel } from "./UserMail.js";

/**
 * Inbound mail for the zone, phases 0.5 and 1 of doc/USER_MAIL.md: the zone's aliases
 * (contact@, admin@, …), which replace Cloudflare Email Routing, and users' forwards.
 *
 * The zone's MX is SendGrid (mx.sendgrid.net); Inbound Parse posts each message here as
 * multipart/form-data with the raw MIME ("POST the raw, full MIME message"), the envelope
 * and a SpamAssassin score. A message to an alias (`contact@`, `contact+tag@`) is forwarded
 * to that alias's target; one to a user (`alice@`, `alice+tag@`, `<app>.alice@`) to the
 * address the user confirmed (UserMail.ts), within a daily cap. Mail to any other address
 * of the zone is dropped. Forwarding is mailing-list style: re-sending the original From through our
 * SendGrid would fail the sender's DMARC, so the copy comes from the address it was sent
 * to ("Bob via nsl.sh" <contact@nsl.sh>) with Reply-To set to the original sender.
 *
 * Answers: 2xx when the message is done with (forwarded, or deliberately dropped: spam,
 * duplicate, unknown address, loop, refused by SendGrid), 5xx when SendGrid could not be
 * reached, so Inbound Parse retries. Each target is claimed separately (Message-ID +
 * target), so a retry re-sends only the copies that failed.
 */

/** Inbound Parse caps a message at 30 MB; the form adds its own fields around it. */
export const MAX_INBOUND_BYTES = 40 * 1024 * 1024;

/** Set on every forwarded copy; a message that already carries it is a loop. */
const LOOP_HEADER = "X-Mesh-Forwarded";

const DEDUPE_TTL_SECONDS = 24 * 60 * 60;

/** The Inbound Parse form fields this module reads. */
export interface InboundFields {
  email?: string;      // raw MIME
  envelope?: string;   // JSON {"to": [...], "from": "..."}
  spam_score?: string; // SpamAssassin score, e.g. "-0.1"
}

export interface InboundConfig {
  zone: string;
  /** Alias local part (lowercase, no +tag) → address it is forwarded to. */
  aliases: Record<string, string>;
  spamDrop: number;
  /** Messages forwarded per user per day; aliases are not capped. */
  forwardPerDay: number;
}

export type InboundResult = "forwarded" | "duplicate" | "spam" | "no-recipient" | "loop" | "invalid" | "refused";

export interface InboundOutcome {
  status: number;
  result: InboundResult;
}

/** What handleInbound needs from the outside world; replaced in tests. */
export interface InboundDeps {
  /** Claims a message key; false when it was already claimed (a retry of a handled message). */
  claim(key: string): Promise<boolean>;
  /** Releases a claim, so the retry of a failed message is processed again. */
  release(key: string): Promise<void>;
  /** Sends a SendGrid v3 payload; returns the HTTP status (202 = accepted). */
  send(payload: Record<string, unknown>): Promise<number>;
  /** The user a label belongs to and the address their mail goes to, when forwarding is active. */
  findUser(label: string): Promise<{ uid: string; target: string } | undefined>;
  /** Counts one forwarded message for the user; false once over the daily cap. */
  allowForward(uid: string, perDay: number): Promise<boolean>;
}

/** Constant-time comparison of the URL token. */
export function tokenMatches(given: string, expected: string): boolean {
  const a = Buffer.from(given);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Reads the multipart body Inbound Parse posts (native FormData parser, no dependency). */
export async function readInboundForm(body: Buffer, contentType: string): Promise<InboundFields> {
  const form = await new Response(new Uint8Array(body), { headers: { "content-type": contentType } }).formData();
  const text = (name: string): string | undefined => {
    const value = form.get(name);
    return typeof value === "string" ? value : undefined;
  };
  return { email: text("email"), envelope: text("envelope"), spam_score: text("spam_score") };
}

/** Envelope recipients that belong to the zone, lowercased and deduplicated. */
export function zoneRecipients(envelope: string | undefined, zone: string): string[] {
  let to: unknown;
  try {
    to = envelope ? JSON.parse(envelope)?.to : undefined;
  } catch {
    return [];
  }
  if (!Array.isArray(to)) {
    return [];
  }
  const suffix = `@${zone.toLowerCase()}`;
  const found = to
    .filter((addr): addr is string => typeof addr === "string")
    .map((addr) => addr.trim().toLowerCase())
    .filter((addr) => addr.endsWith(suffix) && /^[a-z0-9._+-]+$/.test(addr.slice(0, -suffix.length)));
  return [...new Set(found)];
}

function firstAddress(field: AddressObject | AddressObject[] | undefined): EmailAddress | undefined {
  const list = Array.isArray(field) ? field : field ? [field] : [];
  return list.flatMap((obj) => obj.value).find((addr) => !!addr.address);
}

function addressText(field: AddressObject | AddressObject[] | undefined): string {
  return (Array.isArray(field) ? field.map((obj) => obj.text).join(", ") : field?.text) || "";
}

/** Header values go into JSON for SendGrid: one line, bounded. */
function oneLine(value: string, max = 900): string {
  return value.replace(/[\r\n]+/g, " ").trim().slice(0, max);
}

/**
 * The SendGrid v3 payload of the forwarded copy: From is the zone address it was sent to,
 * Reply-To the original sender, body and attachments (inline images included) unchanged.
 */
export function buildForward(parsed: ParsedMail, recipients: string[], target: string, zone: string): Record<string, unknown> {
  const sender = firstAddress(parsed.from);
  const replyTo = firstAddress(parsed.replyTo) || sender;
  const shownAs = oneLine(sender?.name || sender?.address || "Unknown sender", 120);

  // SendGrid v3 requires content entries in increasing precedence: text/plain before text/html.
  const content: Array<{ type: string; value: string }> = [];
  if (parsed.text) {
    content.push({ type: "text/plain", value: parsed.text });
  }
  if (parsed.html) {
    content.push({ type: "text/html", value: parsed.html });
  }
  if (content.length === 0) {
    content.push({ type: "text/plain", value: "(empty message)" });
  }

  const headers: Record<string, string> = {
    [LOOP_HEADER]: zone,
    "X-Original-To": oneLine(recipients.join(", ")),
  };
  const originalFrom = oneLine(addressText(parsed.from));
  if (originalFrom) {
    headers["X-Original-From"] = originalFrom;
  }

  const payload: Record<string, unknown> = {
    personalizations: [{ to: [{ email: target }] }],
    from: { email: recipients[0], name: `${shownAs} via ${zone}` },
    subject: oneLine(parsed.subject || "", 998) || "(no subject)",
    content,
    headers,
  };
  if (replyTo?.address) {
    payload.reply_to = { email: replyTo.address, ...(replyTo.name ? { name: oneLine(replyTo.name, 120) } : {}) };
  }
  if (parsed.attachments.length > 0) {
    payload.attachments = parsed.attachments.map((att, index) => {
      const inline = !!att.cid && (att.related || att.contentDisposition === "inline");
      return {
        filename: att.filename || `attachment-${index + 1}`,
        content: att.content.toString("base64"),
        type: att.contentType || "application/octet-stream",
        disposition: inline ? "inline" : "attachment",
        ...(inline ? { content_id: att.cid } : {}),
      };
    });
  }
  return payload;
}

/**
 * Parses the raw message. keepCidLinks: by default mailparser rewrites cid: references in
 * the HTML into data: URIs, which Gmail does not display; the images go out as inline
 * attachments with their Content-ID instead.
 */
export function parseRaw(raw: string): Promise<ParsedMail> {
  return simpleParser(raw, { keepCidLinks: true });
}

/** Dedupe key of one forwarded copy: the Message-ID (or the raw bytes without one) and the target. */
export function messageKey(parsed: ParsedMail, raw: string, target: string): string {
  const id = parsed.messageId?.trim();
  return "mail:in:" + createHash("sha256").update(id || raw).update("\n" + target.toLowerCase()).digest("hex");
}

/**
 * Groups the zone recipients by the target they are forwarded to. `contact+tag@` is the
 * alias `contact`; recipients that are no alias land in `unknown`.
 */
export function routeRecipients(recipients: string[], aliases: Record<string, string>): { targets: Map<string, string[]>; unknown: string[] } {
  const targets = new Map<string, string[]>();
  const unknown: string[] = [];
  for (const addr of recipients) {
    const local = addr.slice(0, addr.lastIndexOf("@")).split("+")[0];
    const target = Object.prototype.hasOwnProperty.call(aliases, local) ? aliases[local] : undefined;
    if (!target) {
      unknown.push(addr);
      continue;
    }
    targets.set(target, [...(targets.get(target) || []), addr]);
  }
  return { targets, unknown };
}

/** Sender domain only: logs never carry the full sender, the subject or the body. */
function senderDomain(parsed: ParsedMail): string {
  return firstAddress(parsed.from)?.address?.split("@")[1]?.toLowerCase() || "?";
}

export async function handleInbound(fields: InboundFields, cfg: InboundConfig, deps: InboundDeps): Promise<InboundOutcome> {
  if (!fields.email) {
    console.warn("[MAIL IN] invalid: no raw message (is 'POST the raw, full MIME message' ticked?)");
    return { status: 200, result: "invalid" };
  }

  const recipients = zoneRecipients(fields.envelope, cfg.zone);
  const { targets, unknown } = routeRecipients(recipients, cfg.aliases);

  // Not an alias: a user with an active forward, or nobody.
  const users = new Map<string, { uid: string; target: string; addrs: string[] }>();
  const nobody: string[] = [];
  for (const addr of unknown) {
    const label = userLabel(addr.slice(0, addr.lastIndexOf("@")));
    const user = label ? await deps.findUser(label) : undefined;
    if (!user) {
      nobody.push(addr);
      continue;
    }
    const entry = users.get(user.uid) || { ...user, addrs: [] };
    entry.addrs.push(addr);
    users.set(user.uid, entry);
  }
  if (nobody.length > 0) {
    console.log(`[MAIL IN] dropped, no such address or forwarding off: to=${nobody.join(",")}`);
  }
  for (const user of users.values()) {
    targets.set(user.target, [...(targets.get(user.target) || []), ...user.addrs]);
  }
  if (targets.size === 0) {
    if (recipients.length === 0) {
      console.log(`[MAIL IN] no-recipient: envelope has no address in ${cfg.zone}`);
    }
    return { status: 200, result: "no-recipient" };
  }

  // A target in the zone comes straight back through the zone's MX and is dropped as a loop.
  // Refuse with a 5xx instead, so Inbound Parse keeps retrying until the config is fixed.
  const zoneSuffix = `@${cfg.zone.toLowerCase()}`;
  const looping = [...targets.keys()].filter((target) => target.toLowerCase().endsWith(zoneSuffix));
  if (looping.length > 0) {
    console.error(`[MAIL IN] alias target ${looping.join(",")} is in ${cfg.zone}: it would loop, set an address outside the zone`);
    return { status: 503, result: "invalid" };
  }

  const score = parseFloat(fields.spam_score || "");
  const parsed = await parseRaw(fields.email);
  const from = senderDomain(parsed);
  const size = Buffer.byteLength(fields.email);
  const to = [...targets.values()].flat().join(",");

  if (!isNaN(score) && score >= cfg.spamDrop) {
    console.log(`[MAIL IN] spam: from=@${from} to=${to} score=${score} size=${size}`);
    return { status: 200, result: "spam" };
  }
  if (parsed.headers.has(LOOP_HEADER.toLowerCase())) {
    console.warn(`[MAIL IN] loop: from=@${from} to=${to} already forwarded`);
    return { status: 200, result: "loop" };
  }

  // The daily cap, counted once per user and message, after the spam and loop drops.
  for (const user of users.values()) {
    if (await deps.allowForward(user.uid, cfg.forwardPerDay)) {
      continue;
    }
    console.warn(`[MAIL IN] dropped, over ${cfg.forwardPerDay} forwards today: to=${user.addrs.join(",")}`);
    const rest = (targets.get(user.target) || []).filter((addr) => !user.addrs.includes(addr));
    if (rest.length > 0) {
      targets.set(user.target, rest);
    } else {
      targets.delete(user.target);
    }
  }
  if (targets.size === 0) {
    return { status: 200, result: "refused" };
  }

  // One copy per target; the message's answer is the worst of them: any copy to retry → 5xx.
  const results: InboundResult[] = [];
  let retry = false;
  for (const [target, addrs] of targets) {
    const outcome = await forwardOne(parsed, fields.email, addrs, target, cfg.zone, deps, { from, size, score });
    retry = retry || outcome.status >= 500;
    results.push(outcome.result);
  }
  if (retry) {
    return { status: 502, result: "refused" };
  }
  for (const result of ["forwarded", "refused", "duplicate"] as const) {
    if (results.includes(result)) {
      return { status: 200, result };
    }
  }
  return { status: 200, result: "refused" };
}

async function forwardOne(
  parsed: ParsedMail, raw: string, recipients: string[], target: string, zone: string, deps: InboundDeps,
  log: { from: string; size: number; score: number },
): Promise<InboundOutcome> {
  const to = recipients.join(",");
  const key = messageKey(parsed, raw, target);
  if (!(await deps.claim(key))) {
    console.log(`[MAIL IN] duplicate: from=@${log.from} to=${to}`);
    return { status: 200, result: "duplicate" };
  }

  let status: number;
  try {
    status = await deps.send(buildForward(parsed, recipients, target, zone));
  } catch (error) {
    await deps.release(key);
    console.error(`[MAIL IN] SendGrid unreachable, Inbound Parse will retry: from=@${log.from} to=${to}`, error);
    return { status: 502, result: "refused" };
  }
  if (status === 202) {
    console.log(`[MAIL IN] forwarded: from=@${log.from} to=${to} size=${log.size} score=${isNaN(log.score) ? "?" : log.score}`);
    return { status: 200, result: "forwarded" };
  }
  if (status === 429 || status >= 500) {
    await deps.release(key);
    console.error(`[MAIL IN] SendGrid answered ${status}, Inbound Parse will retry: from=@${log.from} to=${to}`);
    return { status: 502, result: "refused" };
  }
  // Any other 4xx is permanent for this message (too big, invalid content): retrying cannot help.
  console.error(`[MAIL IN] dropped, SendGrid refused it (${status}): from=@${log.from} to=${to} size=${log.size}`);
  return { status: 200, result: "refused" };
}

/** The production dependencies: Redis for the dedupe claim, SendGrid v3 for the send. */
export const inboundDeps: InboundDeps = {
  findUser: findForward,
  allowForward,
  async claim(key) {
    return (await getRedisClient().set(key, "1", "EX", DEDUPE_TTL_SECONDS, "NX")) === "OK";
  },
  async release(key) {
    await getRedisClient().del(key);
  },
  async send(payload) {
    const apiKey = getSendgridApiKey();
    if (!apiKey) {
      throw new Error("SENDGRID_API_KEY is not set");
    }
    const resp = await fetch("https://api.sendgrid.com/v3/mail/send", {
      method: "POST",
      headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (resp.status !== 202) {
      const detail = await resp.text().catch(() => "");
      console.error(`[MAIL IN] SendGrid ${resp.status}: ${detail.slice(0, 500)}`);
    }
    return resp.status;
  },
};
