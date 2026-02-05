package com.portfolio.tech_stack.auth.controller;

import com.portfolio.tech_stack.auth.dto.AuthResponse;
import com.portfolio.tech_stack.auth.dto.LoginRequest;
import com.portfolio.tech_stack.auth.dto.RegisterRequest;
import com.portfolio.tech_stack.auth.dto.UserInfo;
import com.portfolio.tech_stack.auth.dto.oauth2.OAuth2UserInfo;
import com.portfolio.tech_stack.auth.service.AuthService;
import com.portfolio.tech_stack.configuration.JwtProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;

/**
 * 인증 관련 REST API 컨트롤러
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthRestController {

    private final AuthService authService;
    private final JwtProperties jwtProperties;

    /**
     * 회원가입
     */
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        log.info("회원가입 요청: {}", request.getEmail());

        AuthResponse response = authService.register(request);

        return ResponseEntity.ok(response);
    }

    /**
     * 로그인
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {

        log.info("로그인 요청: {}", request.getProviderId());

        AuthResponse response = authService.login(request, httpRequest, httpResponse);

        return ResponseEntity.ok(response);
    }

    /**
     * 토큰 갱신
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(
            HttpServletRequest request,
            HttpServletResponse response) {

        log.info("토큰 갱신 요청");

        // 쿠키에서 Refresh Token 추출
        String refreshToken = extractRefreshTokenFromCookies(request);

        if (refreshToken == null) {
            return ResponseEntity.badRequest()
                    .body(AuthResponse.builder()
                            .message("리프레시 토큰이 없습니다")
                            .build());
        }

        AuthResponse authResponse = authService.refreshToken(refreshToken, response);

        return ResponseEntity.ok(authResponse);
    }

    /**
     * 로그아웃
     */
    @PostMapping("/logout")
    public ResponseEntity<AuthResponse> logout(
            HttpServletRequest request,
            HttpServletResponse response) {

        log.info("로그아웃 요청");

        // 쿠키에서 Refresh Token 추출
        String refreshToken = extractRefreshTokenFromCookies(request);

        authService.logout(refreshToken, response);

        return ResponseEntity.ok(AuthResponse.builder()
                .message("로그아웃이 완료되었습니다")
                .build());
    }

    /**
     * 현재 사용자 정보 조회
     */
    @GetMapping("/me")
    public ResponseEntity<AuthResponse> getCurrentUser(
            @AuthenticationPrincipal OAuth2UserInfo.CustomUserDetails userDetails) {

        if (userDetails == null) {
            return ResponseEntity.status(401).body(AuthResponse.builder()
                    .message("인증되지 않은 사용자입니다")
                    .build());
        }

        return ResponseEntity.ok(AuthResponse.builder()
                .message("사용자 정보 조회 성공")
                .user(UserInfo.from(userDetails.getUser()))
                .build());
    }

    /**
     * 인증 상태 확인
     */
    @GetMapping("/check")
    public ResponseEntity<AuthResponse> checkAuth(
            @AuthenticationPrincipal OAuth2UserInfo.CustomUserDetails userDetails) {

        boolean authenticated = userDetails != null;

        return ResponseEntity.ok(AuthResponse.builder()
                .message(authenticated ? "인증됨" : "인증되지 않음")
                .user(authenticated ? UserInfo.from(userDetails.getUser()) : null)
                .build());
    }

    /**
     * 아이디 중복 체크
     */
    @GetMapping("/check-providerId")
    public ResponseEntity<AuthResponse> checkProviderId(@RequestParam String providerId) {
        log.info("아이디 중복 체크: {}", providerId);

        boolean available = authService.isProviderIdAvailable(providerId);

        return ResponseEntity.ok(AuthResponse.builder()
                .message(available ? "사용 가능한 아이디입니다" : "이미 사용 중인 아이디입니다")
                .build());
    }

    /**
     * 쿠키에서 Refresh Token 추출
     */
    private String extractRefreshTokenFromCookies(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        if (cookies == null) {
            return null;
        }

        return Arrays.stream(cookies)
                .filter(cookie -> jwtProperties.getCookie().getRefreshTokenName().equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }
}
