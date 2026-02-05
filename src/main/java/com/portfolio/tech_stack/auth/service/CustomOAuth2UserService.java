package com.portfolio.tech_stack.auth.service;

import com.portfolio.tech_stack.auth.dto.oauth2.OAuth2UserInfo;
import com.portfolio.tech_stack.auth.entity.AuthProvider;
import com.portfolio.tech_stack.auth.entity.User;
import com.portfolio.tech_stack.auth.entity.UserRole;
import com.portfolio.tech_stack.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // OAuth2 제공자로부터 사용자 정보 가져오기
        OAuth2User oAuth2User = super.loadUser(userRequest);

        // Provider 이름 가져오기 (google, github)
        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        // OAuth2UserInfo 생성
        OAuth2UserInfo userInfo = OAuth2UserInfo.OAuth2UserInfoFactory.getOAuth2UserInfo(
                registrationId,
                oAuth2User.getAttributes()
        );

        // 사용자 처리 (등록 또는 업데이트)
        User user = processOAuth2User(registrationId, userInfo);

        return new OAuth2UserInfo.CustomUserDetails(user, oAuth2User.getAttributes());
    }

    /**
     * OAuth2 사용자 처리 (provider + providerId 기반)
     */
    private User processOAuth2User(String registrationId, OAuth2UserInfo userInfo) {
        AuthProvider provider = AuthProvider.valueOf(registrationId.toUpperCase());
        String providerId = userInfo.getProviderId();

        // 1. provider + providerId로 기존 사용자 찾기
        Optional<User> existingUser = userRepository.findByProviderAndProviderId(provider, providerId);

        if (existingUser.isPresent()) {
            // 기존 사용자 - 정보 업데이트
            User user = existingUser.get();

            // 프로필 이미지 업데이트
            if (user.getProfileImageUrl() == null && userInfo.getImageUrl() != null) {
                user.setProfileImageUrl(userInfo.getImageUrl());
            }

            // 이름 업데이트
            if (userInfo.getName() != null) {
                user.setName(userInfo.getName());
            }

            // 이메일 업데이트 (GitHub에서 null일 수 있음)
            if (userInfo.getEmail() != null) {
                user.setEmail(userInfo.getEmail());
            }

            // 마지막 로그인 시간 업데이트
            user.setLastLoginAt(LocalDateTime.now());

            log.info("기존 OAuth2 사용자 로그인: {} (provider={}, providerId={})",
                    user.getName(), provider, providerId);

            return userRepository.save(user);
        }

        // 2. 기존 사용자 없음 - 새로 생성
        User newUser = User.builder()
                .provider(provider)
                .providerId(providerId)
                .email(userInfo.getEmail())  // nullable (GitHub에서 null 가능)
                .name(userInfo.getName())
                .profileImageUrl(userInfo.getImageUrl())
                .role(UserRole.ROLE_USER)
                .enabled(true)
                .build();

        newUser.setLastLoginAt(LocalDateTime.now());

        log.info("새 OAuth2 사용자 생성: {} (provider={}, providerId={})",
                newUser.getName(), provider, providerId);

        return userRepository.save(newUser);
    }
}
