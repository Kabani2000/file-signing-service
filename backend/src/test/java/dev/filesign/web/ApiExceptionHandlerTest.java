package dev.filesign.web;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.MultipartException;

import static org.assertj.core.api.Assertions.assertThat;

class ApiExceptionHandlerTest {

    private final ApiExceptionHandler handler = new ApiExceptionHandler();

    @Test
    void mapsMalformedMultipartToBadRequest() {
        ProblemDetail problem = handler.onMalformedMultipart(new MultipartException("boom"));
        assertThat(problem.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
    }

    @Test
    void mapsOversizeUploadToContentTooLarge() {
        ProblemDetail problem = handler.onTooLarge(new MaxUploadSizeExceededException(25L));
        assertThat(problem.getStatus()).isEqualTo(HttpStatus.CONTENT_TOO_LARGE.value());
    }
}
