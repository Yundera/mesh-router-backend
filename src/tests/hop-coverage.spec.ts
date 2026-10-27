import { describe, it } from "mocha";
import { expect } from "chai";
import { hopCoverage } from "../services/HopNames.js";

describe("hop name coverage (gateway 1.6 readiness)", () => {
  it("lists the boxes with routes that hold no hop certificate", () => {
    const cov = hopCoverage(
      ["routes:sources", "routes:a@x.com:agent", "routes:a@x.com:tunnel", "routes:b@x.com:tunnel", "routes:c@x.com:agent"],
      new Set(["a@x.com", "c@x.com", "gone@x.com"])
    );
    expect(cov.boxes).to.deep.equal([
      { uid: "a@x.com", sources: ["agent", "tunnel"] },
      { uid: "b@x.com", sources: ["tunnel"] },
      { uid: "c@x.com", sources: ["agent"] },
    ]);
    expect(cov.missing).to.deep.equal([{ uid: "b@x.com", sources: ["tunnel"] }]);
  });

  it("is ready when every box holds one", () => {
    expect(hopCoverage(["routes:a@x.com:agent"], new Set(["a@x.com"])).missing).to.deep.equal([]);
    expect(hopCoverage([], new Set()).boxes).to.deep.equal([]);
  });
});
