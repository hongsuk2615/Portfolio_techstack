package com.portfolio.tech_stack.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "jwt")
@Data
public class JwtProperties {

    private String secret;
    private Long accessTokenExpiration;
    private Long refreshTokenExpiration;
    private Cookie cookie = new Cookie();

    @Data
    public static class Cookie {
        private String accessTokenName;
        private String refreshTokenName;
        private String domain;
        private Boolean secure;
        private String sameSite;
    }
}
