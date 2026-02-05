package com.portfolio.tech_stack.auth.service;

import com.portfolio.tech_stack.auth.dto.oauth2.OAuth2UserInfo;
import com.portfolio.tech_stack.auth.entity.AuthProvider;
import com.portfolio.tech_stack.auth.entity.User;
import com.portfolio.tech_stack.auth.entity.UserRole;
import com.portfolio.tech_stack.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * OIDC (OpenID Connect) 사용자 처리 서비스 (Google 등)
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOidcUserService extends OidcUserService {

    private final UserRepository userRepository;

    @Override
    @Transactional
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        // OIDC 제공자로부터 사용자 정보 가져오기
        OidcUser oidcUser = super.loadUser(userRequest);

        // Provider 이름 가져오기 (google)
        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        // OAuth2UserInfo 생성
        OAuth2UserInfo userInfo = OAuth2UserInfo.OAuth2UserInfoFactory.getOAuth2UserInfo(
                registrationId,
                oidcUser.getAttributes()
        );

        // 사용자 처리 (등록 또는 업데이트)
        User user = processOidcUser(registrationId, userInfo);

        // OIDC 전용 생성자 사용
        return new OAuth2UserInfo.CustomUserDetails(user, oidcUser.getAttributes(), oidcUser.getIdToken(), oidcUser.getUserInfo());
    }

    /**
     * OIDC 사용자 처리 (provider + providerId 기반)
     */
    private User processOidcUser(String registrationId, OAuth2UserInfo userInfo) {
        AuthProvider provider = AuthProvider.valueOf(registrationId.toUpperCase());
        String providerId = userInfo.getProviderId();

        // 1. provider + providerId로 기존 사용자 찾기
        Optional<User> existingUser = userRepository.findByProviderAndProviderId(provider, providerId);

        if (existingUser.isPresent()) {

            User user = existingUser.get();

            // 마지막 로그인 시간 업데이트
            user.setLastLoginAt(LocalDateTime.now());

            log.info("기존 OIDC 사용자 로그인: {} (provider={}, providerId={})",
                    user.getName(), provider, providerId);

            return userRepository.save(user);
        }

        // 2. 기존 사용자 없음 - 새로 생성
        User newUser = User.builder()
                .provider(provider)
                .providerId(providerId)
                .email(userInfo.getEmail())
                .name(userInfo.getName())
                .profileImageUrl(userInfo.getImageUrl())
                .role(UserRole.ROLE_USER)
                .enabled(true)
                .build();

        newUser.setLastLoginAt(LocalDateTime.now());

        log.info("새 OIDC 사용자 생성: {} (provider={}, providerId={})",
                newUser.getName(), provider, providerId);

        return userRepository.save(newUser);
    }
}
