package com.portfolio.tech_stack.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/api/**")) // REST API요청의 경우 csrf 비활성화

                // 경로별 권한설정
                .authorizeHttpRequests(auth -> auth
                        /* 누구나 접근가능한 경로
                        *  정적소스들
                        *  메인페이지
                        *  로그인페이지
                        *  에러페이지
                        * */
                        .requestMatchers(
                                "/css/**",
                                "/js/**",
                                "/",
                                "/auth/**",
                                "/error"
                                ).permitAll()
                        .anyRequest().authenticated()
                );

        return http.build();
    }
}
