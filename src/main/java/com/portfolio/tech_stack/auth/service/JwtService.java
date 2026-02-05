package com.portfolio.tech_stack.auth.service;

import com.portfolio.tech_stack.auth.entity.User;
import com.portfolio.tech_stack.configuration.JwtProperties;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class JwtService {

    private final JwtProperties jwtProperties;
    private SecretKey secretKey;

    @PostConstruct
    public void init() {
        // Secret을 SecretKey 객체로 변환 (애플리케이션 시작 시 1번만)
        this.secretKey = Keys.hmacShaKeyFor(
            jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8)
        );
    }

    /**
     * Access Token 생성
     */
    public String generateAccessToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getId());
        claims.put("provider", user.getProvider().name());
        claims.put("providerId", user.getProviderId());
        claims.put("role", user.getRole().name());
        claims.put("type", "ACCESS");

        // subject = "provider:providerId" 형식
        String username = user.getProvider().name() + ":" + user.getProviderId();

        return Jwts.builder()
                .claims(claims)
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + jwtProperties.getAccessTokenExpiration()))
                .signWith(secretKey)
                .compact();
    }

    /**
     * Refresh Token 생성
     */
    public String generateRefreshToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getId());
        claims.put("type", "REFRESH");

        return Jwts.builder()
                .claims(claims)
                .subject(user.getId().toString())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + jwtProperties.getRefreshTokenExpiration()))
                .signWith(secretKey)
                .compact();
    }

    /**
     * JWT 토큰 검증 및 Claims 추출
     */
    public Claims validateAndParseClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            log.error("JWT 토큰이 만료되었습니다: {}", e.getMessage());
            throw new RuntimeException("토큰이 만료되었습니다", e);
        } catch (UnsupportedJwtException e) {
            log.error("지원하지 않는 JWT 토큰입니다: {}", e.getMessage());
            throw new RuntimeException("지원하지 않는 토큰입니다", e);
        } catch (MalformedJwtException e) {
            log.error("잘못된 형식의 JWT 토큰입니다: {}", e.getMessage());
            throw new RuntimeException("잘못된 형식의 토큰입니다", e);
        } catch (SecurityException e) {
            log.error("JWT 서명 검증에 실패했습니다: {}", e.getMessage());
            throw new RuntimeException("유효하지 않은 서명입니다", e);
        } catch (IllegalArgumentException e) {
            log.error("JWT 토큰이 비어있거나 null입니다: {}", e.getMessage());
            throw new RuntimeException("토큰이 비어있습니다", e);
        }
    }

    /**
     * 토큰에서 username 추출 ("provider:providerId" 형식)
     */
    public String extractUsername(String token) {
        Claims claims = validateAndParseClaims(token);
        return claims.getSubject();
    }

    /**
     * 토큰에서 사용자 ID 추출
     */
    public Long extractUserId(String token) {
        Claims claims = validateAndParseClaims(token);
        return claims.get("userId", Long.class);
    }

    /**
     * 토큰 유효성 검사
     */
    public boolean isTokenValid(String token) {
        try {
            validateAndParseClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 토큰 타입 확인 (ACCESS or REFRESH)
     */
    public String getTokenType(String token) {
        Claims claims = validateAndParseClaims(token);
        return claims.get("type", String.class);
    }
}
