package dev.filesign.web;

import dev.filesign.signing.CadesSigningService;
import dev.filesign.signing.SignatureReport;
import dev.filesign.signing.Signer;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;

@RestController
@RequestMapping("/api")
public class SignatureController {

    private static final int BUFFER_SIZE = 16 * 1024;

    private final CadesSigningService signingService;
    private final Signer signer;

    public SignatureController(CadesSigningService signingService, Signer signer) {
        this.signingService = signingService;
        this.signer = signer;
    }

    @PostMapping(value = "/sign", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public SignatureReport sign(@RequestParam("file") MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            throw new IllegalArgumentException("Uploaded file is empty");
        }

        DigestResult digest = digestOf(file);
        return signingService.sign(digest.bytes(), safeFileName(file.getOriginalFilename()), digest.size());
    }

    /**
     * The multipart filename is fully attacker-controlled, so reduce it to a bare basename and
     * strip control characters before it reaches the report or a client's {@code download}
     * attribute. It never touches the filesystem here (only the digest is signed), so this is
     * defence in depth, not the only guard.
     */
    private static String safeFileName(String raw) {
        if (raw == null) {
            return "upload.bin";
        }
        int lastSeparator = Math.max(raw.lastIndexOf('/'), raw.lastIndexOf('\\'));
        String name = raw.substring(lastSeparator + 1).replaceAll("\\p{Cntrl}", "").trim();
        return name.isEmpty() ? "upload.bin" : name;
    }

    /**
     * The signer certificate as PEM, so a verifier can fetch the trust anchor for
     * {@code openssl cms -verify} without cloning the repo.
     */
    @GetMapping(value = "/certificate", produces = MediaType.TEXT_PLAIN_VALUE)
    public String certificate() {
        X509Certificate certificate = signer.signingCertificate().getCertificate();
        try {
            Base64.Encoder encoder = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII));
            return "-----BEGIN CERTIFICATE-----\n"
                    + encoder.encodeToString(certificate.getEncoded())
                    + "\n-----END CERTIFICATE-----\n";
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("Failed to encode signer certificate", e);
        }
    }

    /**
     * Streams the upload through a {@link DigestInputStream}, computing the SHA-256 without
     * ever holding the whole file in memory — signing only needs the 32-byte digest.
     */
    private DigestResult digestOf(MultipartFile file) throws IOException {
        MessageDigest sha256 = newSha256();
        long size = 0;
        byte[] buffer = new byte[BUFFER_SIZE];
        try (InputStream raw = file.getInputStream();
             DigestInputStream digestStream = new DigestInputStream(raw, sha256)) {
            int read;
            while ((read = digestStream.read(buffer)) != -1) {
                size += read;
            }
        }
        return new DigestResult(sha256.digest(), size);
    }

    private static MessageDigest newSha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required but unavailable", e);
        }
    }

    private record DigestResult(byte[] bytes, long size) {
    }
}
