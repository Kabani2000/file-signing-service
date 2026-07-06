package dev.filesign.web;

import dev.filesign.config.SigningProperties;
import dev.filesign.signing.CadesSigningService;
import dev.filesign.signing.LocalKeySigner;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class SignatureControllerTest {

    private static final LocalKeySigner SIGNER = new LocalKeySigner(
            new SigningProperties("classpath:demo/demo-keystore.p12", "demo-password", "demo-signer"));

    private final MockMvc mockMvc = MockMvcBuilders
            .standaloneSetup(new SignatureController(new CadesSigningService(SIGNER), SIGNER))
            .setControllerAdvice(new ApiExceptionHandler())
            .build();

    @Test
    void signsAnUploadAndReturnsTheFullReport() throws Exception {
        byte[] content = "some contract text".getBytes(StandardCharsets.UTF_8);
        String expectedSha256 = HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(content));

        mockMvc.perform(multipart("/api/sign")
                        .file(new MockMultipartFile("file", "contract.txt", "text/plain", content)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.fileName").value("contract.txt"))
                .andExpect(jsonPath("$.fileSizeBytes").value(content.length))
                .andExpect(jsonPath("$.fileSha256Hex").value(expectedSha256))
                .andExpect(jsonPath("$.signatureFormat").value("CAdES-BASELINE-B"))
                .andExpect(jsonPath("$.packaging").value("DETACHED"))
                .andExpect(jsonPath("$.signatureFileName").value("contract.txt.p7s"))
                .andExpect(jsonPath("$.certificateSelfSigned").value(true))
                .andExpect(jsonPath("$.signatureP7sBase64").isNotEmpty());
    }

    @Test
    void rejectsAnEmptyUploadWithBadRequest() throws Exception {
        mockMvc.perform(multipart("/api/sign")
                        .file(new MockMultipartFile("file", "empty.txt", "text/plain", new byte[0])))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.detail").value("Uploaded file is empty"));
    }

    @Test
    void rejectsARequestWithoutAFilePart() throws Exception {
        mockMvc.perform(multipart("/api/sign"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void reducesAttackerControlledFilenameToABasename() throws Exception {
        mockMvc.perform(multipart("/api/sign")
                        .file(new MockMultipartFile("file", "../../../../etc/passwd", "text/plain", "data".getBytes())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.fileName").value("passwd"))
                .andExpect(jsonPath("$.signatureFileName").value("passwd.p7s"));
    }

    @Test
    void servesTheSignerCertificateAsPem() throws Exception {
        String pem = mockMvc.perform(get("/api/certificate"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        assertThat(pem)
                .startsWith("-----BEGIN CERTIFICATE-----")
                .contains("-----END CERTIFICATE-----");
    }
}
