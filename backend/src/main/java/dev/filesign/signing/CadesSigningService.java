package dev.filesign.signing;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;

/**
 * Produces a detached CAdES-BASELINE-B signature over the SHA-256 digest of an uploaded file,
 * using EU DSS for the CMS/CAdES assembly and a {@link Signer} for the raw signature value.
 *
 * <p>Design notes (performance &amp; concurrency):
 * <ul>
 *   <li>We sign a 32-byte <b>digest</b>, never the file bytes — signing cost is independent
 *       of file size, and the service holds O(1) memory per request (the digest is streamed in
 *       {@code SignatureController}).</li>
 *   <li>{@link CAdESService} and {@link CommonCertificateVerifier} are created per request:
 *       construction is cheap (no I/O at B-level), and it keeps every request free of shared
 *       mutable state. The genuinely stateful JCA machinery lives behind {@link Signer},
 *       which also creates it per call.</li>
 *   <li>ECDSA P-256 is used for the signature operation — materially faster than RSA on the
 *       signing (hot) path.</li>
 * </ul>
 */
@Service
public class CadesSigningService {

    private static final String SIGNATURE_FORMAT = "CAdES-BASELINE-B";

    private final Signer signer;

    public CadesSigningService(Signer signer) {
        this.signer = signer;
    }

    public SignatureReport sign(byte[] sha256Digest, String fileName, long fileSizeBytes) {
        Instant signingTime = Instant.now();

        DigestDocument document = new DigestDocument(
                DigestAlgorithm.SHA256, Base64.getEncoder().encodeToString(sha256Digest), fileName);

        CAdESSignatureParameters parameters = new CAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setSigningCertificate(signer.signingCertificate());
        parameters.setCertificateChain(signer.certificateChain());
        parameters.bLevel().setSigningDate(Date.from(signingTime));

        CAdESService service = new CAdESService(new CommonCertificateVerifier());
        ToBeSigned dataToSign = service.getDataToSign(document, parameters);
        SignatureValue signatureValue =
                new SignatureValue(signer.algorithm(), signer.sign(dataToSign.getBytes()));
        DSSDocument signed = service.signDocument(document, parameters, signatureValue);

        byte[] p7s = readAll(signed);
        return buildReport(fileName, fileSizeBytes, sha256Digest, signingTime, p7s);
    }

    private SignatureReport buildReport(String fileName, long fileSizeBytes, byte[] digest,
                                        Instant signingTime, byte[] p7s) {
        X509Certificate certificate = signer.signingCertificate().getCertificate();
        boolean selfSigned = certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal());

        return new SignatureReport(
                fileName,
                fileSizeBytes,
                HexFormat.of().formatHex(digest),
                SIGNATURE_FORMAT,
                "DETACHED",
                "SHA-256",
                describeSigningKey(certificate),
                DateTimeFormatter.ISO_INSTANT.format(signingTime),
                certificate.getSubjectX500Principal().getName(),
                certificate.getIssuerX500Principal().getName(),
                certificate.getSerialNumber().toString(),
                certificate.getNotBefore().toInstant().toString(),
                certificate.getNotAfter().toInstant().toString(),
                selfSigned,
                fileName + ".p7s",
                p7s.length,
                Base64.getEncoder().encodeToString(p7s));
    }

    private static String describeSigningKey(X509Certificate certificate) {
        if (certificate.getPublicKey() instanceof ECPublicKey ec) {
            return "ECDSA (P-" + ec.getParams().getCurve().getField().getFieldSize() + ")";
        }
        return certificate.getPublicKey().getAlgorithm();
    }

    private static byte[] readAll(DSSDocument document) {
        try (InputStream in = document.openStream()) {
            return in.readAllBytes();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read signed document", e);
        }
    }
}
