package dev.filesign.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration of the signing key source.
 *
 * <p>In this demo the key lives in a bundled PKCS#12 keystore, loaded by
 * {@code LocalKeySigner}. The rest of the code depends only on the {@code Signer}
 * interface, so a KMS/HSM-backed implementation replaces these properties wholesale.
 */
@ConfigurationProperties(prefix = "signing")
public record SigningProperties(
        String keystoreLocation,
        String keystorePassword,
        String keyAlias) {
}
