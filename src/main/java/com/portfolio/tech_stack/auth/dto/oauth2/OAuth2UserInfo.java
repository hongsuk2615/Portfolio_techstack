package com.portfolio.tech_stack.auth.dto.oauth2;

import com.portfolio.tech_stack.auth.entity.AuthProvider;
import com.portfolio.tech_stack.auth.entity.User;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

/**
 * OAuth2 제공자별 사용자 정보 인터페이스
 */
public interface OAuth2UserInfo {

    /**
     * OAuth2 제공자의 ID
     */
    String getProviderId();
    String getEmail();
    String getName();
    String getImageUrl();

    /**
     * OAuth2 제공자에 따라 적절한 UserInfo 객체 생성
     */
    class OAuth2UserInfoFactory {

        public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
            AuthProvider provider = AuthProvider.valueOf(registrationId.toUpperCase());

            switch (provider) {
                case GOOGLE :
                    return new GoogleOAuth2UserInfo(attributes);
                case GITHUB :
                    return new GitHubOAuth2UserInfo(attributes);
                default : throw new IllegalArgumentException("지원하지 않는 OAuth2 제공자입니다: " + registrationId);
            }
        }
    }

    @RequiredArgsConstructor
    class CustomUserDetails implements UserDetails, OAuth2User, OidcUser {

        @Getter
        private final User user;
        private Map<String, Object> attributes;
        private OidcIdToken idToken;
        private OidcUserInfo userInfo;

        // OAuth2 전용 생성자
        public CustomUserDetails(User user, Map<String, Object> attributes) {
            this.user = user;
            this.attributes = attributes;
        }

        // OIDC 전용 생성자
        public CustomUserDetails(User user, Map<String, Object> attributes, OidcIdToken idToken, OidcUserInfo userInfo) {
            this.user = user;
            this.attributes = attributes;
            this.idToken = idToken;
            this.userInfo = userInfo;
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return Collections.singletonList(
                new SimpleGrantedAuthority(user.getRole().name())
            );
        }

        @Override
        public String getPassword() {
            return user.getPassword();
        }

        @Override
        public String getUsername() {
            // "provider:providerId" 형식 (email이 null일 수 있으므로)
            return user.getProvider().name() + ":" + user.getProviderId();
        }

        @Override
        public boolean isEnabled() {
            return user.getEnabled();
        }

        // OAuth2User 메서드

        @Override
        public Map<String, Object> getAttributes() {
            return attributes;
        }

        @Override
        public String getName() {
            // OAuth2 principalName으로 사용 (null이면 안 됨)
            return user.getProvider().name() + ":" + user.getProviderId();
        }

        // OidcUser 메서드

        @Override
        public Map<String, Object> getClaims() {
            return attributes != null ? attributes : Collections.emptyMap();
        }

        @Override
        public OidcUserInfo getUserInfo() {
            return userInfo;
        }

        @Override
        public OidcIdToken getIdToken() {
            return idToken;
        }
    }
}
