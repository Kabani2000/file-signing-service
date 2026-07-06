package dev.filesign.signing;

import dev.filesign.config.SigningProperties;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * {@link Signer} backed by a private key in a local PKCS#12 keystore.
 *
 * <p>The keystore is read <b>once</b> at startup; the resulting {@link PrivateKey} and
 * certificate chain are immutable and safe to share across request threads. The stateful
 * {@link Signature} instance is created per {@link #sign(byte[])} call — that object is
 * the one piece of JCA machinery that is genuinely not thread-safe.
 */
@Component
public class LocalKeySigner implements Signer {

    private final PrivateKey privateKey;
    private final CertificateToken signingCertificate;
    private final List<CertificateToken> certificateChain;

    public LocalKeySigner(SigningProperties properties) {
        Resource resource = new DefaultResourceLoader().getResource(properties.keystoreLocation());
        char[] password = properties.keystorePassword().toCharArray();

        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream in = resource.getInputStream()) {
                keyStore.load(in, password);
            }

            String alias = resolveAlias(keyStore, properties.keyAlias());
            this.privateKey = (PrivateKey) keyStore.getKey(alias, password);
            if (this.privateKey == null) {
                throw new IllegalStateException("No private key found for alias '" + alias + "'");
            }

            Certificate[] chain = keyStore.getCertificateChain(alias);
            if (chain == null || chain.length == 0) {
                throw new IllegalStateException("No certificate chain found for alias '" + alias + "'");
            }
            List<CertificateToken> tokens = new ArrayList<>(chain.length);
            for (Certificate certificate : chain) {
                tokens.add(new CertificateToken((X509Certificate) certificate));
            }
            this.certificateChain = List.copyOf(tokens);
            this.signingCertificate = tokens.getFirst();
        } catch (GeneralSecurityException | java.io.IOException e) {
            throw new IllegalStateException(
                    "Failed to load signing keystore from " + properties.keystoreLocation(), e);
        }
    }

    private static String resolveAlias(KeyStore keyStore, String configuredAlias) throws KeyStoreException {
        if (configuredAlias != null && !configuredAlias.isBlank()) {
            return configuredAlias;
        }
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                return alias;
            }
        }
        throw new IllegalStateException("Keystore contains no private key entry");
    }

    @Override
    public SignatureAlgorithm algorithm() {
        return SignatureAlgorithm.ECDSA_SHA256;
    }

    @Override
    public byte[] sign(byte[] data) {
        try {
            Signature signature = Signature.getInstance(algorithm().getJCEId());
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to compute signature value", e);
        }
    }

    @Override
    public CertificateToken signingCertificate() {
        return signingCertificate;
    }

    @Override
    public List<CertificateToken> certificateChain() {
        return certificateChain;
    }
}
