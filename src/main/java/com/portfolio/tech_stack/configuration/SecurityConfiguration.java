package com.portfolio.tech_stack.configuration;

import com.portfolio.tech_stack.auth.filter.JwtAuthenticationFilter;
import com.portfolio.tech_stack.auth.handler.OAuth2AuthenticationFailureHandler;
import com.portfolio.tech_stack.auth.handler.OAuth2AuthenticationSuccessHandler;
import com.portfolio.tech_stack.auth.service.CustomOAuth2UserService;
import com.portfolio.tech_stack.auth.service.CustomOidcUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomOidcUserService customOidcUserService;
    private final OAuth2AuthenticationSuccessHandler oAuth2SuccessHandler;
    private final OAuth2AuthenticationFailureHandler oAuth2FailureHandler;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // CSRF 설정
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/api/**")) // REST API 요청은 CSRF 비활성화

                // 세션 정책: JWT 사용으로 STATELESS
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // 경로별 권한 설정
                .authorizeHttpRequests(auth -> auth
                        // 누구나 접근 가능한 경로
                        .requestMatchers(
                                "/css/**",
                                "/js/**",
                                "/favicon.ico",
                                "/",
                                "/auth/login",
                                "/auth/register",
                                "/api/auth/login",
                                "/api/auth/register",
                                "/api/auth/check",
                                "/api/auth/check-providerId",
                                "/error"
                        ).permitAll()
                        // 나머지는 인증 필요 (/user/info 등)
                        .anyRequest().authenticated()
                )

                // OAuth2 로그인 설정
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/auth/login")  // 로그인 페이지
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(customOAuth2UserService)  // 일반 OAuth2 (GitHub 등)
                                .oidcUserService(customOidcUserService))  // OIDC (Google 등)
                        .successHandler(oAuth2SuccessHandler)  // 성공 핸들러 (JWT 발급)
                        .failureHandler(oAuth2FailureHandler)  // 실패 핸들러
                )

                // JWT 인증 필터 추가 (UsernamePasswordAuthenticationFilter 앞에)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * 비밀번호 암호화 (BCrypt)
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
