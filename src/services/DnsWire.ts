import * as dgram from "dgram";

/**
 * A minimal DNS client for the one question Node's resolver cannot answer: what a zone's
 * own authoritative server says about a child (the referral). Node's resolver only reads
 * the answer section, and a public resolver hands back the child's own NS set, so neither
 * shows a parent that delegates to fewer nameservers than the child lists (the 2026-11-03
 * drill: Cloudflare delegated wisera to nss1 only, the zone listed nss1 + nss2).
 *
 * One UDP query, recursion off, NS records read from the answer and authority sections.
 */

export interface WireRecord {
  name: string;
  type: number;
  /** NS: the target name; other types: not decoded */
  data?: string;
}

export interface WireResponse {
  id: number;
  rcode: number;
  truncated: boolean;
  answers: WireRecord[];
  authority: WireRecord[];
}

export const TYPE_NS = 2;

function norm(name: string): string {
  return name.toLowerCase().replace(/\.+$/, "");
}

/** A query for `name`/`type`, recursion not desired. Pure. */
export function encodeQuery(id: number, name: string, type: number): Buffer {
  const labels = norm(name).split(".").filter(Boolean);
  const parts: Buffer[] = [];
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id & 0xffff, 0);
  header.writeUInt16BE(0x0000, 2); // QR=0, opcode 0, RD=0
  header.writeUInt16BE(1, 4); // QDCOUNT
  parts.push(header);
  for (const label of labels) {
    const b = Buffer.from(label, "ascii");
    if (b.length > 63) throw new Error(`label too long: ${label}`);
    parts.push(Buffer.from([b.length]), b);
  }
  const tail = Buffer.alloc(5);
  tail.writeUInt8(0, 0);
  tail.writeUInt16BE(type, 1);
  tail.writeUInt16BE(1, 3); // IN
  parts.push(tail);
  return Buffer.concat(parts);
}

/** A (possibly compressed) name at `offset`: the name and the offset after it. */
function readName(buf: Buffer, offset: number): { name: string; next: number } {
  const labels: string[] = [];
  let pos = offset;
  let next = -1;
  for (let hops = 0; hops < 64; hops++) {
    if (pos >= buf.length) throw new Error("name past the end");
    const len = buf[pos];
    if (len === 0) {
      if (next < 0) next = pos + 1;
      return { name: labels.join("."), next };
    }
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= buf.length) throw new Error("pointer past the end");
      if (next < 0) next = pos + 2;
      pos = ((len & 0x3f) << 8) | buf[pos + 1];
      continue;
    }
    if (pos + 1 + len > buf.length) throw new Error("label past the end");
    labels.push(buf.toString("ascii", pos + 1, pos + 1 + len));
    pos += 1 + len;
  }
  throw new Error("name loop");
}

/** The response's answer and authority records (NS targets decoded). Pure; throws when malformed. */
export function parseResponse(buf: Buffer): WireResponse {
  if (buf.length < 12) throw new Error("short response");
  const id = buf.readUInt16BE(0);
  const flags = buf.readUInt16BE(2);
  const qd = buf.readUInt16BE(4), an = buf.readUInt16BE(6), ns = buf.readUInt16BE(8);
  let pos = 12;
  for (let i = 0; i < qd; i++) pos = readName(buf, pos).next + 4;
  const readRecords = (count: number): WireRecord[] => {
    const out: WireRecord[] = [];
    for (let i = 0; i < count; i++) {
      const { name, next } = readName(buf, pos);
      if (next + 10 > buf.length) throw new Error("record past the end");
      const type = buf.readUInt16BE(next);
      const rdlen = buf.readUInt16BE(next + 8);
      const rdata = next + 10;
      if (rdata + rdlen > buf.length) throw new Error("rdata past the end");
      out.push({ name: norm(name), type, ...(type === TYPE_NS ? { data: norm(readName(buf, rdata).name) } : {}) });
      pos = rdata + rdlen;
    }
    return out;
  };
  const answers = readRecords(an);
  const authority = readRecords(ns);
  return { id, rcode: flags & 0x0f, truncated: (flags & 0x0200) !== 0, answers, authority };
}

/**
 * The NS set `name` gets from the server at `ip`: from the answer (the server holds the
 * child zone) or the authority section (a referral). [] = no NS for that name there;
 * null = no usable answer (timeout, error code, truncated, malformed).
 */
export function nsFromResponse(res: WireResponse, name: string): string[] | null {
  if (res.rcode !== 0 || res.truncated) return null;
  const owner = norm(name);
  const pick = (rrs: WireRecord[]) => rrs.filter((r) => r.type === TYPE_NS && r.name === owner && r.data).map((r) => r.data as string);
  const fromAnswer = pick(res.answers);
  return [...new Set(fromAnswer.length ? fromAnswer : pick(res.authority))].sort();
}

/** Ask `ip` (port 53, UDP, no recursion) for the NS of `name`. */
export function queryNs(ip: string, name: string, timeoutMs = 3000): Promise<string[] | null> {
  return new Promise((resolve) => {
    const id = Math.floor(Math.random() * 0x10000);
    const socket = dgram.createSocket(ip.includes(":") ? "udp6" : "udp4");
    let done = false;
    const finish = (value: string[] | null) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      socket.close();
      resolve(value);
    };
    const timer = setTimeout(() => finish(null), timeoutMs);
    socket.on("error", () => finish(null));
    socket.on("message", (msg) => {
      try {
        const res = parseResponse(msg);
        if (res.id !== id) return;
        finish(nsFromResponse(res, name));
      } catch {
        finish(null);
      }
    });
    socket.send(encodeQuery(id, name, TYPE_NS), 53, ip, (err) => {
      if (err) finish(null);
    });
  });
}
