/**
 * CertificateAuthority.ts - Private PKI for mesh-router
 *
 * Provides a Certificate Authority service that issues short-lived certificates
 * (72h TTL) to agents/tunnels, enabling the gateway to verify SSL connections.
 *
 * Features:
 * - Auto-generates CA if cert/key files don't exist
 * - Signs CSRs with CN enforcement (must match userid)
 * - 72-hour certificate validity
 */

import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import forge from 'node-forge';
import { getServerDomain } from '../configuration/config.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration via environment variables
const CA_CERT_PATH = process.env.CA_CERT_PATH || path.join(__dirname, '../../config/ca-cert.pem');
const CA_KEY_PATH = process.env.CA_KEY_PATH || path.join(__dirname, '../../config/ca-key.pem');

// Certificate validity in hours (default: 72 hours)
const CERT_VALIDITY_HOURS = parseInt(process.env.CERT_VALIDITY_HOURS || '72', 10);

// CA validity in years (default: 10 years)
const CA_VALIDITY_YEARS = 10;

// Module state
let caCert: forge.pki.Certificate | null = null;
let caKey: forge.pki.rsa.PrivateKey | null = null;
let caCertPem: string = '';

/**
 * Generate a self-signed root CA certificate and private key
 */
function generateRootCA(commonName: string, organization: string): { cert: string; key: string } {
  console.log('[CA] Generating new root CA certificate...');

  // Generate RSA key pair (2048 bits is standard for CA)
  const keys = forge.pki.rsa.generateKeyPair(2048);

  // Create certificate
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';

  // Validity period
  const now = new Date();
  cert.validity.notBefore = now;
  cert.validity.notAfter = new Date(now.getTime() + CA_VALIDITY_YEARS * 365 * 24 * 60 * 60 * 1000);

  // Subject and issuer (self-signed)
  const attrs = [
    { name: 'commonName', value: commonName },
    { name: 'organizationName', value: organization },
    { shortName: 'OU', value: 'Mesh Router PKI' },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);

  // CA extensions
  cert.setExtensions([
    {
      name: 'basicConstraints',
      cA: true,
      critical: true,
    },
    {
      name: 'keyUsage',
      keyCertSign: true,
      cRLSign: true,
      critical: true,
    },
    {
      name: 'subjectKeyIdentifier',
    },
  ]);

  // Self-sign the certificate
  cert.sign(keys.privateKey, forge.md.sha256.create());

  // Convert to PEM format
  const certPem = forge.pki.certificateToPem(cert);
  const keyPem = forge.pki.privateKeyToPem(keys.privateKey);

  console.log('[CA] Root CA certificate generated successfully');
  console.log(`[CA]   Common Name: ${commonName}`);
  console.log(`[CA]   Organization: ${organization}`);
  console.log(`[CA]   Valid until: ${cert.validity.notAfter.toISOString()}`);

  return { cert: certPem, key: keyPem };
}

/**
 * Initialize the Certificate Authority
 * - Loads existing CA cert/key from files
 * - Auto-generates CA if files don't exist
 */
export async function initializeCA(): Promise<void> {
  const caCertPath = CA_CERT_PATH;
  const caKeyPath = CA_KEY_PATH;

  // Check if CA files exist
  const certExists = fs.existsSync(caCertPath);
  const keyExists = fs.existsSync(caKeyPath);

  if (!certExists || !keyExists) {
    console.log('[CA] CA certificate not found, generating new CA...');
    console.log(`[CA]   Cert path: ${caCertPath}`);
    console.log(`[CA]   Key path: ${caKeyPath}`);

    // Generate new CA
    const { cert, key } = generateRootCA('Mesh Router CA', 'NSL.SH');

    // Ensure config directory exists
    const configDir = path.dirname(caCertPath);
    if (!fs.existsSync(configDir)) {
      fs.mkdirSync(configDir, { recursive: true });
    }

    // Write CA files
    fs.writeFileSync(caCertPath, cert, { mode: 0o644 });
    fs.writeFileSync(caKeyPath, key, { mode: 0o600 });
    console.log('[CA] CA certificate generated and saved');
  }

  // Load CA certificate and key
  try {
    caCertPem = fs.readFileSync(caCertPath, 'utf-8');
    const caKeyPem = fs.readFileSync(caKeyPath, 'utf-8');

    caCert = forge.pki.certificateFromPem(caCertPem);
    caKey = forge.pki.privateKeyFromPem(caKeyPem) as forge.pki.rsa.PrivateKey;

    console.log('[CA] Certificate Authority initialized');
    console.log(`[CA]   Cert path: ${caCertPath}`);
    console.log(`[CA]   Valid until: ${caCert.validity.notAfter.toISOString()}`);
  } catch (error) {
    console.error('[CA] Failed to load CA certificate/key:', error);
    throw new Error('Failed to initialize Certificate Authority');
  }
}

/**
 * Get the CA public certificate in PEM format
 */
export function getCACertificate(): string {
  if (!caCertPem) {
    throw new Error('Certificate Authority not initialized');
  }
  return caCertPem;
}

/**
 * Sign a Certificate Signing Request (CSR)
 *
 * @param csrPem - The CSR in PEM format
 * @param userId - The expected user ID (must match CN in CSR)
 * @param publicIp - Optional public IP to include as SAN (for nip.io support)
 * @returns Signed certificate and expiry date
 */
export async function signCSR(
  csrPem: string,
  userId: string,
  publicIp?: string
): Promise<{ certificate: string; expiresAt: Date }> {
  if (!caCert || !caKey) {
    throw new Error('Certificate Authority not initialized');
  }

  // Parse the CSR
  // Note: node-forge types don't export CertificateRequest, use any
  let csr: ReturnType<typeof forge.pki.certificationRequestFromPem>;
  try {
    csr = forge.pki.certificationRequestFromPem(csrPem);
  } catch (error) {
    throw new Error('Invalid CSR format');
  }

  // Verify CSR signature
  if (!csr.verify()) {
    throw new Error('CSR signature verification failed');
  }

  // Extract CN from CSR
  const cnAttr = csr.subject.getField('CN');
  const cn = cnAttr ? cnAttr.value : null;

  // Enforce CN must match userId
  if (cn !== userId) {
    throw new Error(`CSR Common Name (${cn}) does not match userId (${userId})`);
  }

  // Create certificate
  const cert = forge.pki.createCertificate();
  cert.publicKey = csr.publicKey as forge.pki.PublicKey;

  // Generate unique serial number (must be positive, so prepend '00' to ensure high bit is clear)
  const serialBytes = forge.random.getBytesSync(15);
  const serial = '00' + forge.util.bytesToHex(serialBytes);
  cert.serialNumber = serial;

  // Set validity period
  const now = new Date();
  const expiresAt = new Date(now.getTime() + CERT_VALIDITY_HOURS * 60 * 60 * 1000);
  cert.validity.notBefore = now;
  cert.validity.notAfter = expiresAt;

  // Copy subject from CSR
  cert.setSubject(csr.subject.attributes);

  // Set issuer from CA certificate
  cert.setIssuer(caCert.subject.attributes);

  // Build extensions for end-entity certificate
  const extensions: Parameters<typeof cert.setExtensions>[0] = [
    {
      name: 'basicConstraints',
      cA: false,
    },
    {
      name: 'keyUsage',
      digitalSignature: true,
      keyEncipherment: true,
    },
    {
      name: 'extKeyUsage',
      serverAuth: true,
      clientAuth: true,
    },
    {
      name: 'subjectKeyIdentifier',
    },
    {
      name: 'authorityKeyIdentifier',
      // Pass the issuer certificate to correctly derive the authority key identifier
      // from the CA's public key (not the subject's key)
      issuer: caCert,
    },
  ];

  // Build comprehensive SANs for all access patterns
  // This enables HTTPS connections via:
  // 1. Gateway-routed traffic (SNI matching *.serverDomain)
  // 2. CF Worker direct access (*.nip.io)
  // 3. Direct IP access (https://[IP])
  const altNames: Array<{type: number; value?: string; ip?: string}> = [];

  // 1. Wildcard for serverDomain (gateway-routed traffic)
  // e.g., *.inojob.com matches casaos-wisera.inojob.com
  try {
    const serverDomain = getServerDomain();
    altNames.push({ type: 2, value: `*.${serverDomain}` });  // DNS wildcard
    console.log(`[CA]   SAN: *.${serverDomain}`);
  } catch (e) {
    console.log('[CA]   Warning: SERVER_DOMAIN not configured, skipping wildcard SAN');
  }

  // 2. Wildcard for nip.io (CF Worker direct access)
  // Covers any {something}.nip.io hostname
  altNames.push({ type: 2, value: '*.nip.io' });  // DNS wildcard
  console.log('[CA]   SAN: *.nip.io');

  // 3. Raw IP SAN (direct IP access via https://[IP])
  if (publicIp) {
    altNames.push({ type: 7, ip: publicIp });  // IP address
    console.log(`[CA]   SAN: IP ${publicIp}`);
  }

  if (altNames.length > 0) {
    extensions.push({
      name: 'subjectAltName',
      altNames,
    });
  }

  cert.setExtensions(extensions);

  // Sign with CA private key
  cert.sign(caKey, forge.md.sha256.create());

  // Convert to PEM
  const certPem = forge.pki.certificateToPem(cert);

  console.log(`[CA] Certificate issued for userId: ${userId}`);
  console.log(`[CA]   Serial: ${serial.substring(0, 16)}...`);
  console.log(`[CA]   Expires: ${expiresAt.toISOString()}`);

  return {
    certificate: certPem,
    expiresAt,
  };
}

/**
 * Check if the CA is initialized
 */
export function isCAInitialized(): boolean {
  return caCert !== null && caKey !== null;
}
