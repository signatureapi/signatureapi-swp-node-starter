import { X509Certificate } from "node:crypto";
import { ContentInfo, id_signedData, SignedData } from "@peculiar/asn1-cms";
import { AsnConvert } from "@peculiar/asn1-schema";

/**
 * The `certificates` of a `cms` sign response: the signer's certificate (leaf first), then its
 * issuers up to but excluding the self-signed root. eID Easy's CMS carries only the leaf; the
 * issuers come from `pades_dss_data.certificates`, which also holds OCSP responder certificates
 * and the root, both dropped here.
 */

const OCSP_SIGNING = "1.3.6.1.5.5.7.3.9";
const MAX_DEPTH = 8;

function serialHex(bytes: ArrayBuffer | string): string {
  const hex = typeof bytes === "string" ? bytes : Buffer.from(bytes).toString("hex");
  return hex.toUpperCase().replace(/^0+/, "");
}

/** The certificate the CMS's (first) SignerInfo names, out of the CMS's own certificate set. */
export function signerCertificate(cms: Uint8Array): X509Certificate {
  const info = AsnConvert.parse(cms, ContentInfo);
  if (info.contentType !== id_signedData) {
    throw new Error("the CMS is not SignedData");
  }
  const signedData = AsnConvert.parse(info.content, SignedData);
  const certificates = (signedData.certificates ?? []).flatMap((choice) =>
    choice.certificate ? [new X509Certificate(Buffer.from(AsnConvert.serialize(choice.certificate)))] : [],
  );
  const serial = signedData.signerInfos[0]?.sid.issuerAndSerialNumber?.serialNumber;
  const leaf =
    (serial && certificates.find((certificate) => serialHex(certificate.serialNumber) === serialHex(serial))) ||
    certificates[0];
  if (!leaf) {
    throw new Error("the CMS carries no signer certificate");
  }
  return leaf;
}

function parse(pem: string): X509Certificate | null {
  try {
    return new X509Certificate(pem);
  } catch {
    return null;
  }
}

function isSelfSigned(certificate: X509Certificate): boolean {
  return certificate.checkIssued(certificate) && certificate.verify(certificate.publicKey);
}

export function certificateChain(cms: Uint8Array, pool: string[]): string[] {
  const leaf = signerCertificate(cms);
  const candidates = pool
    .map(parse)
    .filter((certificate): certificate is X509Certificate => certificate !== null)
    .filter((certificate) => !certificate.keyUsage?.includes(OCSP_SIGNING));
  const chain = [leaf];
  let current = leaf;
  while (chain.length < MAX_DEPTH && !isSelfSigned(current)) {
    const issuer = candidates.find((c) => current.checkIssued(c) && current.verify(c.publicKey));
    if (!issuer || isSelfSigned(issuer) || chain.some((c) => c.fingerprint256 === issuer.fingerprint256)) {
      break;
    }
    chain.push(issuer);
    current = issuer;
  }
  return chain.map((certificate) => certificate.toString());
}
