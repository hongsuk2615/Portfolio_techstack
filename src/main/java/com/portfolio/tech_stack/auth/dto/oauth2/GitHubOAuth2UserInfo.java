package com.portfolio.tech_stack.auth.dto.oauth2;

import lombok.extern.slf4j.Slf4j;

import java.util.Map;

/**
 * GitHub OAuth2 사용자 정보
 */
@Slf4j
public class GitHubOAuth2UserInfo implements OAuth2UserInfo {

    private final Map<String, Object> attributes;

    public GitHubOAuth2UserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
        System.out.println(attributes.toString());
    }

    @Override
    public String getProviderId() {
        return String.valueOf(attributes.get("id"));
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }

    @Override
    public String getImageUrl() {
        return (String) attributes.get("avatar_url");
    }
}
