import { createHash, timingSafeEqual } from "node:crypto";
import { simpleParser, ParsedMail, AddressObject, EmailAddress } from "mailparser";
import { getSendgridApiKey } from "../configuration/config.js";
import { getRedisClient } from "../redis/redisClient.js";

/**
 * Inbound mail for the zone, phase 0 of doc/USER_MAIL.md: the catch-all that replaces
 * Cloudflare Email Routing.
 *
 * The zone's MX is SendGrid (mx.sendgrid.net); Inbound Parse posts each message here as
 * multipart/form-data with the raw MIME ("POST the raw, full MIME message"), the envelope
 * and a SpamAssassin score. Every message addressed to the zone is forwarded to one
 * address (MAIL_CATCHALL), mailing-list style: re-sending the original From through our
 * SendGrid would fail the sender's DMARC, so the copy comes from the address it was sent
 * to ("Bob via nsl.sh" <contact@nsl.sh>) with Reply-To set to the original sender.
 *
 * Answers: 2xx when the message is done with (forwarded, or deliberately dropped: spam,
 * duplicate, not for the zone, loop, refused by SendGrid), 5xx when SendGrid could not be
 * reached, so Inbound Parse retries. Retries are deduplicated on the Message-ID.
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
  catchall: string;
  spamDrop: number;
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

/** Dedupe key of a message: its Message-ID, or the raw bytes when it has none. */
export function messageKey(parsed: ParsedMail, raw: string): string {
  const id = parsed.messageId?.trim();
  return "mail:in:" + createHash("sha256").update(id || raw).digest("hex");
}

/** Sender domain only: logs never carry the full sender, the subject or the body. */
function senderDomain(parsed: ParsedMail): string {
  return firstAddress(parsed.from)?.address?.split("@")[1]?.toLowerCase() || "?";
}

export async function handleInbound(fields: InboundFields, cfg: InboundConfig, deps: InboundDeps): Promise<InboundOutcome> {
  // A target in the zone comes straight back through the zone's MX and is dropped as a loop.
  // Refuse with a 5xx instead, so Inbound Parse keeps retrying until the config is fixed.
  if (cfg.catchall.toLowerCase().endsWith(`@${cfg.zone.toLowerCase()}`)) {
    console.error(`[MAIL IN] MAIL_CATCHALL ${cfg.catchall} is in ${cfg.zone}: it would loop, set an address outside the zone`);
    return { status: 503, result: "invalid" };
  }
  if (!fields.email) {
    console.warn("[MAIL IN] invalid: no raw message (is 'POST the raw, full MIME message' ticked?)");
    return { status: 200, result: "invalid" };
  }

  const recipients = zoneRecipients(fields.envelope, cfg.zone);
  if (recipients.length === 0) {
    console.log(`[MAIL IN] no-recipient: envelope has no address in ${cfg.zone}`);
    return { status: 200, result: "no-recipient" };
  }

  const score = parseFloat(fields.spam_score || "");
  const parsed = await parseRaw(fields.email);
  const from = senderDomain(parsed);
  const size = Buffer.byteLength(fields.email);

  if (!isNaN(score) && score >= cfg.spamDrop) {
    console.log(`[MAIL IN] spam: from=@${from} to=${recipients.join(",")} score=${score} size=${size}`);
    return { status: 200, result: "spam" };
  }
  if (parsed.headers.has(LOOP_HEADER.toLowerCase())) {
    console.warn(`[MAIL IN] loop: from=@${from} to=${recipients.join(",")} already forwarded`);
    return { status: 200, result: "loop" };
  }

  const key = messageKey(parsed, fields.email);
  if (!(await deps.claim(key))) {
    console.log(`[MAIL IN] duplicate: from=@${from} to=${recipients.join(",")}`);
    return { status: 200, result: "duplicate" };
  }

  let status: number;
  try {
    status = await deps.send(buildForward(parsed, recipients, cfg.catchall, cfg.zone));
  } catch (error) {
    await deps.release(key);
    console.error(`[MAIL IN] SendGrid unreachable, Inbound Parse will retry: from=@${from}`, error);
    return { status: 502, result: "refused" };
  }
  if (status === 202) {
    console.log(`[MAIL IN] forwarded: from=@${from} to=${recipients.join(",")} size=${size} score=${isNaN(score) ? "?" : score}`);
    return { status: 200, result: "forwarded" };
  }
  if (status === 429 || status >= 500) {
    await deps.release(key);
    console.error(`[MAIL IN] SendGrid answered ${status}, Inbound Parse will retry: from=@${from}`);
    return { status: 502, result: "refused" };
  }
  // Any other 4xx is permanent for this message (too big, invalid content): retrying cannot help.
  console.error(`[MAIL IN] dropped, SendGrid refused it (${status}): from=@${from} to=${recipients.join(",")} size=${size}`);
  return { status: 200, result: "refused" };
}

/** The production dependencies: Redis for the dedupe claim, SendGrid v3 for the send. */
export const inboundDeps: InboundDeps = {
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
