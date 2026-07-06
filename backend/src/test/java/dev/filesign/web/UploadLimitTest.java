package dev.filesign.web;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Runs against a real Tomcat: multipart size limits are enforced by the servlet container,
 * so a MockMvc test cannot exercise the 413 path.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "spring.servlet.multipart.max-file-size=1KB")
class UploadLimitTest {

    @LocalServerPort
    private int port;

    @Test
    void rejectsAnOversizedUploadWithContentTooLarge() {
        MultiValueMap<String, Object> parts = new LinkedMultiValueMap<>();
        parts.add("file", new ByteArrayResource(new byte[4 * 1024]) {
            @Override
            public String getFilename() {
                return "big.bin";
            }
        });

        Integer status = RestClient.create("http://localhost:" + port)
                .post()
                .uri("/api/sign")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .body(parts)
                .exchange((request, response) -> response.getStatusCode().value());

        assertThat(status).isEqualTo(413);
    }
}
