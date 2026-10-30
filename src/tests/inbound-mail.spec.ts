import { describe, it } from "mocha";
import { expect } from "chai";
import {
  buildForward, handleInbound, InboundDeps, parseRaw, readInboundForm, tokenMatches, zoneRecipients,
} from "../services/InboundMail.js";

/**
 * Inbound mail catch-all (SendGrid Inbound Parse → forward). Pure: no Firestore, Redis or
 * SendGrid; the claim/send dependencies are recorded fakes.
 */

const ZONE = "inojob.com";
const CFG = { zone: ZONE, catchall: "team@example.org", spamDrop: 5 };
const PNG = Buffer.from("89504e470d0a1a0a0000000d49484452", "hex");

function rawMail(opts: { messageId?: string; extraHeaders?: string } = {}): string {
  return [
    `From: "Bob Sender" <bob@gmail.com>`,
    `To: contact@${ZONE}`,
    `Subject: Hello there`,
    `Message-ID: ${opts.messageId ?? "<abc123@mail.gmail.com>"}`,
    ...(opts.extraHeaders ? [opts.extraHeaders] : []),
    `MIME-Version: 1.0`,
    `Content-Type: multipart/mixed; boundary="mix"`,
    ``,
    `--mix`,
    `Content-Type: multipart/related; boundary="rel"`,
    ``,
    `--rel`,
    `Content-Type: multipart/alternative; boundary="alt"`,
    ``,
    `--alt`,
    `Content-Type: text/plain; charset=UTF-8`,
    ``,
    `Plain body`,
    `--alt`,
    `Content-Type: text/html; charset=UTF-8`,
    ``,
    `<p>Html body <img src="cid:logo@x"></p>`,
    `--alt--`,
    `--rel`,
    `Content-Type: image/png`,
    `Content-ID: <logo@x>`,
    `Content-Disposition: inline; filename="logo.png"`,
    `Content-Transfer-Encoding: base64`,
    ``,
    PNG.toString("base64"),
    `--rel--`,
    `--mix`,
    `Content-Type: application/pdf; name="report.pdf"`,
    `Content-Disposition: attachment; filename="report.pdf"`,
    `Content-Transfer-Encoding: base64`,
    ``,
    Buffer.from("%PDF-1.4 test").toString("base64"),
    `--mix--`,
    ``,
  ].join("\r\n");
}

function fields(overrides: Record<string, string | undefined> = {}) {
  return {
    email: rawMail(),
    envelope: JSON.stringify({ to: [`contact@${ZONE}`], from: "bob@gmail.com" }),
    spam_score: "-0.1",
    ...overrides,
  };
}

function fakeDeps(sendStatus: number | Error = 202) {
  const claimed = new Set<string>();
  const sent: Array<Record<string, unknown>> = [];
  const released: string[] = [];
  const deps: InboundDeps = {
    async claim(key) {
      if (claimed.has(key)) return false;
      claimed.add(key);
      return true;
    },
    async release(key) {
      claimed.delete(key);
      released.push(key);
    },
    async send(payload) {
      sent.push(payload);
      if (sendStatus instanceof Error) throw sendStatus;
      return sendStatus;
    },
  };
  return { deps, sent, released, claimed };
}

describe("inbound mail input checks", () => {
  it("compares the URL token exactly", () => {
    expect(tokenMatches("s3cret", "s3cret")).to.equal(true);
    expect(tokenMatches("s3cre", "s3cret")).to.equal(false);
    expect(tokenMatches("S3cret", "s3cret")).to.equal(false);
  });

  it("keeps only envelope recipients of the zone", () => {
    const env = JSON.stringify({
      to: [`Contact@${ZONE}`, `contact@${ZONE}`, "x@other.org", `evil@sub.${ZONE}`, `a b@${ZONE}`, 42, `abuse+tag@${ZONE}`],
    });
    expect(zoneRecipients(env, ZONE)).to.deep.equal([`contact@${ZONE}`, `abuse+tag@${ZONE}`]);
    expect(zoneRecipients("not json", ZONE)).to.deep.equal([]);
    expect(zoneRecipients(undefined, ZONE)).to.deep.equal([]);
  });

  it("reads the Inbound Parse multipart form", async () => {
    const form = new FormData();
    form.set("email", rawMail());
    form.set("envelope", JSON.stringify({ to: [`contact@${ZONE}`] }));
    form.set("spam_score", "1.2");
    form.set("subject", "ignored");
    const req = new Request("http://localhost/", { method: "POST", body: form });
    const body = Buffer.from(await req.arrayBuffer());
    const read = await readInboundForm(body, req.headers.get("content-type") || "");
    expect(read.email).to.equal(rawMail());
    expect(read.spam_score).to.equal("1.2");
    expect(JSON.parse(read.envelope || "{}").to).to.deep.equal([`contact@${ZONE}`]);
  });
});

describe("inbound mail forward", () => {
  it("rewrites the sender and keeps body, attachments and inline images", async () => {
    const payload = buildForward(await parseRaw(rawMail()), [`contact@${ZONE}`], CFG.catchall, ZONE);
    expect(payload.from).to.deep.equal({ email: `contact@${ZONE}`, name: `Bob Sender via ${ZONE}` });
    expect(payload.reply_to).to.deep.equal({ email: "bob@gmail.com", name: "Bob Sender" });
    expect(payload.personalizations).to.deep.equal([{ to: [{ email: CFG.catchall }] }]);
    expect(payload.subject).to.equal("Hello there");

    const content = payload.content as Array<{ type: string; value: string }>;
    expect(content.map((c) => c.type)).to.deep.equal(["text/plain", "text/html"]);
    expect(content[1].value).to.contain("cid:logo@x");

    const atts = payload.attachments as Array<Record<string, string>>;
    const logo = atts.find((a) => a.filename === "logo.png")!;
    expect(logo.disposition).to.equal("inline");
    expect(logo.content_id).to.equal("logo@x");
    expect(Buffer.from(logo.content, "base64").equals(PNG)).to.equal(true);
    const pdf = atts.find((a) => a.filename === "report.pdf")!;
    expect(pdf.disposition).to.equal("attachment");
    expect(pdf.type).to.equal("application/pdf");

    const headers = payload.headers as Record<string, string>;
    expect(headers["X-Original-From"]).to.contain("bob@gmail.com");
    expect(headers["X-Original-To"]).to.equal(`contact@${ZONE}`);
    expect(headers["X-Mesh-Forwarded"]).to.equal(ZONE);
  });

  it("prefers the original Reply-To", async () => {
    const parsed = await parseRaw(rawMail({ extraHeaders: "Reply-To: replies@example.net" }));
    expect(buildForward(parsed, [`contact@${ZONE}`], CFG.catchall, ZONE).reply_to).to.deep.equal({ email: "replies@example.net" });
  });

  it("forwards once and drops the retry of a handled message", async () => {
    const { deps, sent } = fakeDeps();
    expect(await handleInbound(fields(), CFG, deps)).to.deep.equal({ status: 200, result: "forwarded" });
    expect(await handleInbound(fields(), CFG, deps)).to.deep.equal({ status: 200, result: "duplicate" });
    expect(sent).to.have.length(1);
  });

  it("drops spam, loops, foreign recipients and raw-less posts without sending", async () => {
    const { deps, sent } = fakeDeps();
    expect((await handleInbound(fields({ spam_score: "5.0" }), CFG, deps)).result).to.equal("spam");
    expect((await handleInbound(fields({ email: rawMail({ extraHeaders: `X-Mesh-Forwarded: ${ZONE}` }) }), CFG, deps)).result).to.equal("loop");
    expect((await handleInbound(fields({ envelope: JSON.stringify({ to: ["x@other.org"] }) }), CFG, deps)).result).to.equal("no-recipient");
    expect((await handleInbound(fields({ email: undefined }), CFG, deps)).result).to.equal("invalid");
    expect(sent).to.have.length(0);
  });

  it("asks for a retry when SendGrid is unreachable or busy, and processes the retry", async () => {
    for (const failure of [new Error("ECONNRESET"), 503, 429] as const) {
      const { deps, released } = fakeDeps(failure);
      expect(await handleInbound(fields(), CFG, deps)).to.deep.equal({ status: 502, result: "refused" });
      expect(released).to.have.length(1);
      expect(await deps.claim(released[0])).to.equal(true);
    }
  });

  it("refuses with a retry while the catch-all target is in the zone", async () => {
    const { deps, sent } = fakeDeps();
    const looping = { ...CFG, catchall: `contact@${ZONE}` };
    expect(await handleInbound(fields(), looping, deps)).to.deep.equal({ status: 503, result: "invalid" });
    expect(sent).to.have.length(0);
  });

  it("drops a message SendGrid refuses for good, without a retry", async () => {
    const { deps, released } = fakeDeps(413);
    expect(await handleInbound(fields(), CFG, deps)).to.deep.equal({ status: 200, result: "refused" });
    expect(released).to.have.length(0);
  });
});
