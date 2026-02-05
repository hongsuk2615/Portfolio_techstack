package com.portfolio.tech_stack.auth.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Component
@Slf4j
public class
OAuth2AuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                       HttpServletResponse response,
                                       AuthenticationException exception) throws IOException, ServletException {

        log.error("OAuth2 로그인 실패: {}", exception.getMessage());

        String errorMessage = exception.getLocalizedMessage();

        // 에러 메시지를 URL 인코딩
        String encodedMessage = URLEncoder.encode(errorMessage, StandardCharsets.UTF_8);

        // 로그인 페이지로 리다이렉트 (에러 메시지 포함)
        getRedirectStrategy().sendRedirect(
                request,
                response,
                "/auth/login?error=true&message=" + encodedMessage
        );
    }
}
