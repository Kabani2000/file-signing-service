package dev.filesign.signing;

import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;

import java.util.List;

/**
 * The raw signing operation over already-assembled to-be-signed bytes.
 *
 * <p>The interface is shaped by what a production key holder (KMS/HSM, Smart-ID/Mobile-ID)
 * actually offers: it signs bytes and presents a certificate — it never exposes the private
 * key. {@link LocalKeySigner} is the demo implementation backed by a bundled PKCS#12; a
 * KMS- or Smart-ID-backed implementation plugs in without touching the CAdES assembly.
 */
public interface Signer {

    SignatureAlgorithm algorithm();

    byte[] sign(byte[] data);

    CertificateToken signingCertificate();

    List<CertificateToken> certificateChain();
}
