package com.portfolio.tech_stack.auth.service;

import com.portfolio.tech_stack.auth.entity.RefreshToken;
import com.portfolio.tech_stack.auth.entity.User;
import com.portfolio.tech_stack.auth.repository.RefreshTokenRepository;
import com.portfolio.tech_stack.configuration.JwtProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;

    /**
     * Refresh Token 생성 및 DB 저장
     */
    @Transactional
    public RefreshToken createRefreshToken(User user, String deviceInfo, String ipAddress) {
        // JWT Refresh Token 생성
        String tokenString = jwtService.generateRefreshToken(user);

        // 만료 시간 계산
        LocalDateTime expiryDate = LocalDateTime.now()
                .plusSeconds(jwtProperties.getRefreshTokenExpiration() / 1000);

        // RefreshToken 엔티티 생성 및 저장
        RefreshToken refreshToken = RefreshToken.builder()
                .token(tokenString)
                .user(user)
                .expiryDate(expiryDate)
                .deviceInfo(deviceInfo)
                .ipAddress(ipAddress)
                .revoked(false)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    /**
     * 토큰 문자열로 RefreshToken 찾기
     */
    public RefreshToken findByToken(String token) {
        return refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("리프레시 토큰을 찾을 수 없습니다"));
    }

    /**
     * Refresh Token 유효성 검증 (만료, 무효화 체크)
     */
    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().isBefore(LocalDateTime.now())) {
            refreshTokenRepository.delete(token);
            throw new RuntimeException("리프레시 토큰이 만료되었습니다. 다시 로그인해주세요.");
        }

        if (token.getRevoked()) {
            throw new RuntimeException("리프레시 토큰이 무효화되었습니다. 다시 로그인해주세요.");
        }

        return token;
    }

    /**
     * 특정 사용자의 모든 토큰 무효화 (모든 기기 로그아웃)
     */
    @Transactional
    public void revokeAllUserTokens(User user) {
        refreshTokenRepository.revokeAllUserTokens(user);
        log.info("사용자의 모든 리프레시 토큰을 무효화했습니다: {}", user.getEmail());
    }

    /**
     * 만료된 토큰 정리 (스케줄러에서 호출)
     */
    @Transactional
    public void cleanupExpiredTokens() {
        log.info("만료된 리프레시 토큰 정리를 시작합니다");
        refreshTokenRepository.deleteExpiredTokens(LocalDateTime.now());
        log.info("만료된 리프레시 토큰 정리를 완료했습니다");
    }
}
