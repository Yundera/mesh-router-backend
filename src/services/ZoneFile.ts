import { isIPv4, isIPv6 } from "net";

/**
 * Parser for the static zone file of SERVER_DOMAIN (mesh-router-nameserver
 * docs/architecture.md §9, §10.2): the records nobody derives (mail, site verification,
 * the nameservers' own addresses), kept as server config next to the backend.
 *
 * BIND master-file syntax, the subset a hand-kept zone needs: $ORIGIN, $TTL, `@`,
 * relative names, a blank owner repeating the previous one, `;` comments, parentheses,
 * quoted strings. Types A AAAA CNAME MX TXT CAA SRV NS. SOA is skipped: the primary
 * owns it. Content comes out in PowerDNS API form (absolute names, quoted TXT).
 */

export interface ZoneRecord {
  /** Absolute owner name, lowercase, trailing dot. */
  name: string;
  ttl: number;
  type: string;
  /** PowerDNS API content. */
  content: string;
  line: number;
}

export class ZoneFileError extends Error {
  constructor(public readonly errors: string[]) {
    super(errors.join("\n"));
  }
}

export const DEFAULT_ZONE_TTL = 300;

const TYPES = new Set(["A", "AAAA", "CNAME", "MX", "TXT", "CAA", "SRV", "NS", "SOA"]);
const CLASSES = new Set(["IN"]);
const TTL_UNITS: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400, w: 604800 };

interface Token {
  text: string;
  quoted: boolean;
}

interface Entry {
  line: number;
  /** The line started with whitespace: owner = previous owner. */
  inherit: boolean;
  tokens: Token[];
}

/** Split the file into entries (one per record, parentheses joined), comments dropped. */
function tokenize(text: string, errors: string[]): Entry[] {
  const entries: Entry[] = [];
  let current: Entry | null = null;
  let depth = 0;
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (depth === 0) {
      if (current && current.tokens.length) entries.push(current);
      current = { line: i + 1, inherit: /^[ \t]/.test(raw), tokens: [] };
    }
    let pos = 0;
    while (pos < raw.length) {
      const c = raw[pos];
      if (c === ";") break;
      if (c === " " || c === "\t") { pos++; continue; }
      if (c === "(") { depth++; pos++; continue; }
      if (c === ")") {
        if (depth === 0) errors.push(`line ${i + 1}: unbalanced ')'`);
        else depth--;
        pos++;
        continue;
      }
      if (c === '"') {
        let end = pos + 1;
        let value = "";
        while (end < raw.length && raw[end] !== '"') {
          // keep escapes as written: PowerDNS takes TXT content in the same syntax
          if (raw[end] === "\\" && end + 1 < raw.length) { value += raw[end] + raw[end + 1]; end += 2; continue; }
          value += raw[end++];
        }
        if (end >= raw.length) errors.push(`line ${i + 1}: unterminated quoted string`);
        current!.tokens.push({ text: value, quoted: true });
        pos = end + 1;
        continue;
      }
      let end = pos;
      while (end < raw.length && !" \t;()\"".includes(raw[end])) end++;
      current!.tokens.push({ text: raw.slice(pos, end), quoted: false });
      pos = end;
    }
  }
  if (depth !== 0) errors.push("unbalanced '(' at the end of the file");
  if (current && current.tokens.length) entries.push(current);
  return entries;
}

function parseTtl(text: string): number | null {
  if (/^\d+$/.test(text)) return Number(text);
  if (!/^(?:\d+[smhdw])+$/i.test(text)) return null;
  let total = 0;
  for (const [, n, unit] of text.toLowerCase().matchAll(/(\d+)([smhdw])/g)) total += Number(n) * TTL_UNITS[unit];
  return total;
}

/** `name` made absolute against `origin` (both without/with trailing dot), lowercase. */
function absolute(name: string, origin: string): string {
  if (name === "@") return origin;
  if (name.endsWith(".")) return name.toLowerCase();
  return `${name}.${origin}`.toLowerCase();
}

function isHostname(name: string): boolean {
  return /^(\*\.)?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+$/i.test(name) || name === ".";
}

/** RDATA → PowerDNS content, or an error text. */
function content(type: string, rdata: Token[], origin: string): string | { error: string } {
  const words = rdata.map((t) => t.text);
  const name = (t: string) => {
    const n = absolute(t, origin);
    return isHostname(n) ? n : null;
  };
  const count = (n: number) => (rdata.length === n ? null : { error: `${type} takes ${n} field(s), got ${rdata.length}` });
  switch (type) {
    case "A":
      return count(1) ?? (isIPv4(words[0]) ? words[0] : { error: `not an IPv4 address: ${words[0]}` });
    case "AAAA":
      return count(1) ?? (isIPv6(words[0]) ? words[0].toLowerCase() : { error: `not an IPv6 address: ${words[0]}` });
    case "CNAME":
    case "NS": {
      const bad = count(1);
      if (bad) return bad;
      return name(words[0]) ?? { error: `not a host name: ${words[0]}` };
    }
    case "MX": {
      const bad = count(2);
      if (bad) return bad;
      const target = name(words[1]);
      if (!/^\d+$/.test(words[0]) || !target) return { error: `MX wants <preference> <host>, got ${words.join(" ")}` };
      return `${Number(words[0])} ${target}`;
    }
    case "SRV": {
      const bad = count(4);
      if (bad) return bad;
      const target = name(words[3]);
      if (!words.slice(0, 3).every((w) => /^\d+$/.test(w)) || !target) {
        return { error: `SRV wants <priority> <weight> <port> <host>, got ${words.join(" ")}` };
      }
      return `${words.slice(0, 3).map(Number).join(" ")} ${target}`;
    }
    case "TXT":
      if (rdata.length === 0) return { error: "TXT without a string" };
      return rdata.map((t) => `"${t.quoted ? t.text : t.text.replace(/"/g, '\\"')}"`).join(" ");
    case "CAA": {
      const bad = count(3);
      if (bad) return bad;
      if (!/^\d+$/.test(words[0]) || !/^[a-z0-9]+$/i.test(words[1])) return { error: `CAA wants <flags> <tag> "<value>", got ${words.join(" ")}` };
      return `${Number(words[0])} ${words[1].toLowerCase()} "${words[2]}"`;
    }
    default:
      return { error: `unsupported type ${type}` };
  }
}

/**
 * Parse a zone file for `zone` (no trailing dot needed). Every error is collected and
 * thrown together as a ZoneFileError, so one run shows them all. SOA records are dropped.
 */
export function parseZoneFile(text: string, zone: string, defaultTtl = DEFAULT_ZONE_TTL): ZoneRecord[] {
  const apex = `${zone.replace(/\.+$/, "").toLowerCase()}.`;
  const errors: string[] = [];
  let origin = apex;
  let ttlDefault = defaultTtl;
  let previous: string | null = null;
  const records: ZoneRecord[] = [];

  for (const entry of tokenize(text, errors)) {
    const at = `line ${entry.line}`;
    const tokens = [...entry.tokens];
    const first = tokens[0];
    if (!entry.inherit && !first.quoted && first.text.startsWith("$")) {
      const directive = first.text.toUpperCase();
      if (directive === "$ORIGIN" && tokens.length === 2) {
        origin = absolute(tokens[1].text.endsWith(".") ? tokens[1].text : `${tokens[1].text}.${origin}`, origin);
      } else if (directive === "$TTL" && tokens.length === 2 && parseTtl(tokens[1].text) !== null) {
        ttlDefault = parseTtl(tokens[1].text)!;
      } else {
        errors.push(`${at}: unsupported directive ${tokens.map((t) => t.text).join(" ")}`);
      }
      continue;
    }

    let owner: string;
    if (entry.inherit) {
      if (!previous) { errors.push(`${at}: no owner name and no previous record`); continue; }
      owner = previous;
    } else {
      owner = absolute(tokens.shift()!.text, origin);
    }
    // [ttl] [class] or [class] [ttl], then the type
    let ttl: number | null = null;
    while (tokens.length && !tokens[0].quoted && !TYPES.has(tokens[0].text.toUpperCase())) {
      const word = tokens[0].text;
      if (ttl === null && parseTtl(word) !== null) ttl = parseTtl(word);
      else if (CLASSES.has(word.toUpperCase())) { /* IN */ }
      else break;
      tokens.shift();
    }
    const typeToken = tokens.shift();
    const type = typeToken?.text.toUpperCase();
    if (!type || !TYPES.has(type)) {
      errors.push(`${at}: ${typeToken ? `unsupported type or class ${typeToken.text}` : "no record type"}`);
      continue;
    }
    previous = owner;
    if (owner !== apex && !owner.endsWith(`.${apex}`)) {
      errors.push(`${at}: ${owner} is outside the zone ${apex}`);
      continue;
    }
    if (!isHostname(owner)) {
      errors.push(`${at}: not a valid owner name: ${owner}`);
      continue;
    }
    if (type === "SOA") continue;
    const value = content(type, tokens, origin);
    if (typeof value !== "string") {
      errors.push(`${at}: ${value.error}`);
      continue;
    }
    records.push({ name: owner, ttl: ttl ?? ttlDefault, type, content: value, line: entry.line });
  }
  if (errors.length) throw new ZoneFileError(errors);
  return records;
}
