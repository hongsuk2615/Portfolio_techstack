package com.portfolio.tech_stack.auth.handler;

import com.portfolio.tech_stack.auth.dto.oauth2.OAuth2UserInfo;
import com.portfolio.tech_stack.auth.service.AuthService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Slf4j
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final AuthService authService;

    @Value("${app.oauth2.success-redirect-uri:/user/info}")
    private String redirectUri;

    public OAuth2AuthenticationSuccessHandler(@Lazy AuthService authService) {
        this.authService = authService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                       HttpServletResponse response,
                                       Authentication authentication) throws IOException, ServletException {

        if (response.isCommitted()) {
            log.warn("응답이 이미 커밋되었습니다. 리다이렉트할 수 없습니다.");
            return;
        }

        // 인증된 사용자 정보 가져오기
        OAuth2UserInfo.CustomUserDetails userDetails = (OAuth2UserInfo.CustomUserDetails) authentication.getPrincipal();

        // JWT 토큰 생성 및 HttpOnly 쿠키 설정
        authService.setAuthCookies(userDetails.getUser(), request, response);

        log.info("OAuth2 로그인 성공: {}", userDetails.getUser().getEmail());

        // 대시보드로 리다이렉트
        getRedirectStrategy().sendRedirect(request, response, redirectUri);
    }
}
