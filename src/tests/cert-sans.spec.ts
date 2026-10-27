import { describe, it, before } from "mocha";
import { expect } from "chai";
import fs from "fs";
import os from "os";
import path from "path";
import forge from "node-forge";

// CertificateAuthority reads its paths at import time: point them at a throwaway CA
// before loading it.
const caDir = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-ca-test-"));
process.env.CA_CERT_PATH = path.join(caDir, "ca-cert.pem");
process.env.CA_KEY_PATH = path.join(caDir, "ca-key.pem");
process.env.SERVER_DOMAIN = "inojob.com";

import { getCertExtraSans } from "../configuration/config.js";

function makeCsr(cn: string): string {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = keys.publicKey;
  csr.setSubject([{ name: "commonName", value: cn }]);
  csr.sign(keys.privateKey);
  return forge.pki.certificationRequestToPem(csr);
}

function dnsSans(certPem: string): string[] {
  const cert = forge.pki.certificateFromPem(certPem);
  const ext = cert.getExtension("subjectAltName") as { altNames: { type: number; value: string }[] } | null;
  return (ext?.altNames ?? []).filter((n) => n.type === 2).map((n) => n.value);
}

describe("Certificate SANs", () => {
  let ca: typeof import("../services/CertificateAuthority.js");

  before(async function () {
    this.timeout(30000); // RSA key generation for the throwaway CA
    ca = await import("../services/CertificateAuthority.js");
    await ca.initializeCA();
  });

  it("parses CERT_EXTRA_SANS as a trimmed comma list", () => {
    process.env.CERT_EXTRA_SANS = " *.ip.inojob.com , ,extra.example.com";
    expect(getCertExtraSans()).to.deep.equal(["*.ip.inojob.com", "extra.example.com"]);
    delete process.env.CERT_EXTRA_SANS;
    expect(getCertExtraSans()).to.deep.equal([]);
  });

  it("adds CERT_EXTRA_SANS to the signed certificate", async function () {
    this.timeout(30000);
    process.env.CERT_EXTRA_SANS = "*.ip.inojob.com";
    const { certificate } = await ca.signCSR(makeCsr("user-1"), "user-1", "80.241.218.30");
    delete process.env.CERT_EXTRA_SANS;
    expect(dnsSans(certificate)).to.deep.equal(["*.ip.inojob.com"]);
  });

  it("adds the hop name when given", async function () {
    this.timeout(30000);
    const { certificate } = await ca.signCSR(makeCsr("user-3"), "user-3", undefined, "wisera.box.inojob.com");
    expect(dnsSans(certificate)).to.deep.equal(["wisera.box.inojob.com"]);
  });

  it("issues no user-facing name: no *.<zone>, no *.nip.io", async function () {
    this.timeout(30000);
    const { certificate } = await ca.signCSR(makeCsr("user-2"), "user-2");
    expect(dnsSans(certificate)).to.deep.equal([]);
  });
});
