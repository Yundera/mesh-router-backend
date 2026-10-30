import { describe, it } from "mocha";
import { expect } from "chai";
import { checkForwardTarget, confirmPage, forwardView, hashToken, UserMailError, userLabel } from "../services/UserMail.js";

/** Per-user mail forwarding (UserMail.ts): the pure parts, no Firestore, Redis or SendGrid. */

describe("user mail forwarding", () => {
  it("maps local parts to the user label", () => {
    expect(userLabel("alice")).to.equal("alice");
    expect(userLabel("Alice+Shop")).to.equal("alice");
    expect(userLabel("vaultwarden.alice")).to.equal("alice");
    expect(userLabel("vaultwarden.alice+x")).to.equal("alice");
    expect(userLabel("a.b.alice")).to.equal(undefined);
    expect(userLabel("-alice")).to.equal(undefined);
    expect(userLabel("way-too-long-app-name.alice")).to.equal(undefined);
    expect(userLabel("")).to.equal(undefined);
  });

  it("accepts a plain external target, lowercased", () => {
    expect(checkForwardTarget("  Me@Gmail.com ", "nsl.sh")).to.equal("me@gmail.com");
    expect(checkForwardTarget("a.b+c@mail.example.co.uk", "nsl.sh")).to.equal("a.b+c@mail.example.co.uk");
  });

  it("refuses malformed targets and targets that would loop through the zone", () => {
    for (const bad of ["", "me", "me@", "@gmail.com", "me@localhost", "me@gmail..com", "a b@x.org", 42, undefined,
      "me@nsl.sh", "me@NSL.sh", "me@alice.nsl.sh", `${"a".repeat(250)}@x.org`]) {
      expect(() => checkForwardTarget(bad, "nsl.sh"), String(bad)).to.throw(UserMailError);
    }
    expect(() => checkForwardTarget("me@notnsl.sh", "nsl.sh")).not.to.throw();
  });

  it("shows the stored setting to the box without the token", () => {
    expect(forwardView(undefined, "alice@nsl.sh", true)).to.deep.equal({ enabled: true, address: "alice@nsl.sh", state: "off" });
    const pending = { target: "me@gmail.com", state: "pending" as const, confirmHash: hashToken("t"), confirmExpires: "2030-01-01T00:00:00Z" };
    expect(forwardView(pending, "alice@nsl.sh", true)).to.deep.equal({ enabled: true, address: "alice@nsl.sh", state: "pending", target: "me@gmail.com" });
    const active = { target: "me@gmail.com", state: "active" as const };
    expect(forwardView(active, "alice@nsl.sh", true).state).to.equal("active");
    expect(forwardView(active, "alice@nsl.sh", true, "the address bounced"))
      .to.deep.equal({ enabled: true, address: "alice@nsl.sh", state: "paused", target: "me@gmail.com", reason: "the address bounced" });
  });

  it("escapes the confirmation page", () => {
    const html = confirmPage("<t>", `a "b" & c`, { action: `x" onclick="y`, label: "Go" });
    expect(html).to.contain("&lt;t&gt;").and.contain("a &quot;b&quot; &amp; c").and.contain(`action="x&quot; onclick=&quot;y"`);
    expect(html).not.to.contain("<script");
  });
});
