package dev.filesign.signing;

/**
 * Everything a human (or the reviewer) needs to understand and independently verify
 * what was signed. The {@code signatureP7sBase64} field carries the detached CAdES
 * signature itself, ready to be saved as a {@code .p7s} file.
 */
public record SignatureReport(
        String fileName,
        long fileSizeBytes,
        String fileSha256Hex,
        String signatureFormat,
        String packaging,
        String digestAlgorithm,
        String signatureAlgorithm,
        String signingTime,
        String signerSubjectDn,
        String signerIssuerDn,
        String signerSerialNumber,
        String certificateValidFrom,
        String certificateValidUntil,
        boolean certificateSelfSigned,
        String signatureFileName,
        int signatureSizeBytes,
        String signatureP7sBase64) {
}
