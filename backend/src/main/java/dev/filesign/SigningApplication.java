package dev.filesign;

import dev.filesign.config.SigningProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(SigningProperties.class)
public class SigningApplication {

    public static void main(String[] args) {
        SpringApplication.run(SigningApplication.class, args);
    }
}
