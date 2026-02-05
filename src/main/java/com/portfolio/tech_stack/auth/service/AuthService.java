package com.portfolio.tech_stack.auth.service;

import com.portfolio.tech_stack.auth.dto.AuthResponse;
import com.portfolio.tech_stack.auth.dto.LoginRequest;
import com.portfolio.tech_stack.auth.dto.RegisterRequest;
import com.portfolio.tech_stack.auth.dto.UserInfo;
import com.portfolio.tech_stack.auth.entity.AuthProvider;
import com.portfolio.tech_stack.auth.entity.RefreshToken;
import com.portfolio.tech_stack.auth.entity.User;
import com.portfolio.tech_stack.auth.entity.UserRole;
import com.portfolio.tech_stack.auth.repository.UserRepository;
import com.portfolio.tech_stack.configuration.JwtProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final JwtProperties jwtProperties;

    /**
     * 일반 회원가입 (DEFAULT provider)
     */
    @Transactional
    public AuthResponse register(RegisterRequest request) {
        // providerId 중복 확인
        if (userRepository.existsByProviderAndProviderId(AuthProvider.DEFAULT, request.getProviderId())) {
            throw new RuntimeException("이미 사용 중인 아이디입니다");
        }

        // 새 사용자 생성
        User newUser = User.builder()
                .provider(AuthProvider.DEFAULT)
                .providerId(request.getProviderId())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .name(request.getName())
                .role(UserRole.ROLE_USER)
                .enabled(true)
                .build();

        newUser.setLastLoginAt(LocalDateTime.now());
        userRepository.save(newUser);

        log.info("새 사용자 회원가입: {} (provider=DEFAULT, providerId={})", newUser.getName(), newUser.getProviderId());
        return buildAuthResponse(newUser, "회원가입이 완료되었습니다");
    }

    /**
     * 일반 로그인 (DEFAULT provider)
     */
    @Transactional
    public AuthResponse login(LoginRequest request, HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        // providerId로 사용자 찾기
        User user = userRepository.findByProviderAndProviderId(AuthProvider.DEFAULT, request.getProviderId())
                .orElseThrow(() -> new BadCredentialsException("잘못된 아이디 또는 비밀번호입니다"));

        // 비밀번호 확인
        if (user.getPassword() == null || !passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("잘못된 아이디 또는 비밀번호입니다");
        }

        // 마지막 로그인 시간 업데이트
        user.setLastLoginAt(LocalDateTime.now());
        userRepository.save(user);

        // JWT 토큰 생성 및 쿠키 설정
        setAuthCookies(user, httpRequest, httpResponse);

        log.info("로그인 성공: {} (providerId={})", user.getName(), user.getProviderId());
        return buildAuthResponse(user, "로그인 성공");
    }

    /**
     * Access Token 갱신
     */
    @Transactional
    public AuthResponse refreshToken(String refreshTokenString, HttpServletResponse httpResponse) {
        // Refresh Token 찾기 및 검증
        RefreshToken refreshToken = refreshTokenService.findByToken(refreshTokenString);
        refreshTokenService.verifyExpiration(refreshToken);

        // 사용자 정보 가져오기
        User user = refreshToken.getUser();

        // 새 Access Token 생성
        String newAccessToken = jwtService.generateAccessToken(user);

        // 새 Access Token 쿠키 설정
        Cookie accessTokenCookie = createCookie(
                jwtProperties.getCookie().getAccessTokenName(),
                newAccessToken,
                (int) (jwtProperties.getAccessTokenExpiration() / 1000)
        );
        httpResponse.addCookie(accessTokenCookie);

        log.info("토큰 갱신 성공: {}", user.getName());
        return buildAuthResponse(user, "토큰이 갱신되었습니다");
    }

    /**
     * 로그아웃
     */
    @Transactional
    public void logout(String refreshTokenString, HttpServletResponse httpResponse) {
        if (refreshTokenString != null) {
            try {
                RefreshToken refreshToken = refreshTokenService.findByToken(refreshTokenString);
                refreshToken.setRevoked(true);
                log.info("로그아웃: {}", refreshToken.getUser().getName());
            } catch (Exception e) {
                log.warn("리프레시 토큰 무효화 실패: {}", e.getMessage());
            }
        }

        // 쿠키 삭제
        clearAuthCookies(httpResponse);
    }

    /**
     * 인증 쿠키 설정 (Access + Refresh Token)
     */
    public void setAuthCookies(User user, HttpServletRequest request, HttpServletResponse response) {
        // Access Token 생성
        String accessToken = jwtService.generateAccessToken(user);

        // Refresh Token 생성 및 DB 저장
        String deviceInfo = request.getHeader("User-Agent");
        String ipAddress = request.getRemoteAddr();
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user, deviceInfo, ipAddress);

        // 쿠키 생성
        Cookie accessTokenCookie = createCookie(
                jwtProperties.getCookie().getAccessTokenName(),
                accessToken,
                (int) (jwtProperties.getAccessTokenExpiration() / 1000)
        );

        Cookie refreshTokenCookie = createCookie(
                jwtProperties.getCookie().getRefreshTokenName(),
                refreshToken.getToken(),
                (int) (jwtProperties.getRefreshTokenExpiration() / 1000)
        );

        response.addCookie(accessTokenCookie);
        response.addCookie(refreshTokenCookie);
    }

    /**
     * 인증 쿠키 삭제
     */
    private void clearAuthCookies(HttpServletResponse response) {
        Cookie accessTokenCookie = createCookie(
                jwtProperties.getCookie().getAccessTokenName(),
                "",
                0
        );

        Cookie refreshTokenCookie = createCookie(
                jwtProperties.getCookie().getRefreshTokenName(),
                "",
                0
        );

        response.addCookie(accessTokenCookie);
        response.addCookie(refreshTokenCookie);
    }

    /**
     * HttpOnly 쿠키 생성
     */
    private Cookie createCookie(String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(jwtProperties.getCookie().getSecure());
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);

        if (jwtProperties.getCookie().getDomain() != null) {
            cookie.setDomain(jwtProperties.getCookie().getDomain());
        }

        return cookie;
    }

    /**
     * 아이디 중복 체크 (DEFAULT provider)
     */
    public boolean isProviderIdAvailable(String providerId) {
        return !userRepository.existsByProviderAndProviderId(AuthProvider.DEFAULT, providerId);
    }

    /**
     * AuthResponse 생성 헬퍼 메서드
     */
    private AuthResponse buildAuthResponse(User user, String message) {
        return AuthResponse.builder()
                .message(message)
                .user(UserInfo.builder()
                        .id(user.getId())
                        .email(user.getEmail())
                        .name(user.getName())
                        .profileImageUrl(user.getProfileImageUrl())
                        .role(user.getRole().name())
                        .build())
                .build();
    }
}
