package com.portfolio.tech_stack.auth.dto;

import com.portfolio.tech_stack.auth.entity.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserInfo {

    private Long id;
    private String email;
    private String name;
    private String profileImageUrl;
    private String role;

    /**
     * User 엔티티를 UserInfo DTO로 변환
     */
    public static UserInfo from(User user) {
        return UserInfo.builder()
                .id(user.getId())
                .email(user.getEmail())
                .name(user.getName())
                .profileImageUrl(user.getProfileImageUrl())
                .role(user.getRole().name())
                .build();
    }
}
