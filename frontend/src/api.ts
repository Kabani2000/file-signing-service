export interface SignatureReport {
  fileName: string;
  fileSizeBytes: number;
  fileSha256Hex: string;
  signatureFormat: string;
  packaging: string;
  digestAlgorithm: string;
  signatureAlgorithm: string;
  signingTime: string;
  signerSubjectDn: string;
  signerIssuerDn: string;
  signerSerialNumber: string;
  certificateValidFrom: string;
  certificateValidUntil: string;
  certificateSelfSigned: boolean;
  signatureFileName: string;
  signatureSizeBytes: number;
  signatureP7sBase64: string;
}

export async function signFile(file: File): Promise<SignatureReport> {
  const body = new FormData();
  body.append("file", file);

  const response = await fetch("/api/sign", { method: "POST", body });
  if (!response.ok) {
    const problem = await response.json().catch(() => null);
    throw new Error(problem?.detail ?? `Signing failed (HTTP ${response.status})`);
  }
  return response.json();
}

/** Turns the base64 CAdES signature into a downloadable .p7s blob URL. */
export function p7sDownloadUrl(report: SignatureReport): string {
  const bytes = Uint8Array.from(atob(report.signatureP7sBase64), (c) => c.charCodeAt(0));
  return URL.createObjectURL(new Blob([bytes], { type: "application/pkcs7-signature" }));
}
