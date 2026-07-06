package dev.filesign;

import dev.filesign.config.SigningProperties;
import dev.filesign.signing.CadesSigningService;
import dev.filesign.signing.LocalKeySigner;
import dev.filesign.signing.SignatureReport;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class SigningRoundTripTest {

    private static CadesSigningService newService() throws Exception {
        SigningProperties properties = new SigningProperties(
                "classpath:demo/demo-keystore.p12", "demo-password", "demo-signer");
        return new CadesSigningService(new LocalKeySigner(properties));
    }

    @Test
    void signsAndProducesAVerifiableDetachedCadesSignature() throws Exception {
        CadesSigningService service = newService();
        byte[] content = "Agrello file-signing homework".getBytes(StandardCharsets.UTF_8);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(content);

        SignatureReport report = service.sign(digest, "contract.txt", content.length);

        assertThat(report.signatureFormat()).isEqualTo("CAdES-BASELINE-B");
        assertThat(report.packaging()).isEqualTo("DETACHED");
        assertThat(report.signatureFileName()).isEqualTo("contract.txt.p7s");
        assertThat(report.fileSha256Hex())
                .isEqualTo(HexFormat.of().formatHex(digest));
        assertThat(report.signatureP7sBase64()).isNotBlank();

        assertThat(verifyDetached(report, content)).isTrue();
    }

    @Test
    void failsVerificationWhenContentIsTampered() throws Exception {
        CadesSigningService service = newService();
        byte[] content = "Agrello file-signing homework".getBytes(StandardCharsets.UTF_8);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(content);

        SignatureReport report = service.sign(digest, "contract.txt", content.length);
        byte[] tampered = "Agrello file-signing homework (edited)".getBytes(StandardCharsets.UTF_8);

        assertThatExceptionOfType(CMSException.class)
                .isThrownBy(() -> verifyDetached(report, tampered))
                .withMessageContaining("message-digest");
    }

    /** Verifies the detached CMS against the original content — exactly what {@code openssl cms -verify} does. */
    private boolean verifyDetached(SignatureReport report, byte[] originalContent) throws Exception {
        byte[] p7s = Base64.getDecoder().decode(report.signatureP7sBase64());
        CMSSignedData cms = new CMSSignedData(new CMSProcessableByteArray(originalContent), p7s);

        Store<X509CertificateHolder> certificates = cms.getCertificates();
        SignerInformation signer = cms.getSignerInfos().getSigners().iterator().next();
        @SuppressWarnings("unchecked")
        java.util.Collection<X509CertificateHolder> matches =
                (java.util.Collection<X509CertificateHolder>) certificates.getMatches(signer.getSID());
        X509CertificateHolder certificate = matches.iterator().next();

        return signer.verify(new JcaSimpleSignerInfoVerifierBuilder()
                .setProvider(new BouncyCastleProvider())
                .build(certificate));
    }

}
