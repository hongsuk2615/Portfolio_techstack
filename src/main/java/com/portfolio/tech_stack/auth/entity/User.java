package com.portfolio.tech_stack.auth.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "users",
    uniqueConstraints = {
        @UniqueConstraint(name = "uk_provider_providerId", columnNames = {"provider", "providerId"})
    },
    indexes = {
        @Index(name = "idx_users_email", columnList = "email")
    })
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * Provider (DEFAULT, GOOGLE, GITHUB)
     */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 50)
    private AuthProvider provider;

    /**
     * Provider별 고유 ID
     * - DEFAULT: 사용자 입력 username
     * - GOOGLE: sub (Google user ID)
     * - GITHUB: id (GitHub user ID)
     */
    @Column(nullable = false, length = 255)
    private String providerId;

    /**
     * 이메일 (nullable - GitHub에서 null 가능)
     */
    @Column(length = 255)
    private String email;

    /**
     * 비밀번호 (nullable - OAuth2 사용자는 비밀번호 없음)
     */
    @Column
    private String password;

    @Column(nullable = false, length = 100)
    private String name;

    @Column(length = 500)
    private String profileImageUrl;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 50)
    @Builder.Default
    private UserRole role = UserRole.ROLE_USER;

    @Column(nullable = false)
    @Builder.Default
    private Boolean enabled = true;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(nullable = false)
    private LocalDateTime updatedAt;

    @Column
    private LocalDateTime lastLoginAt;
}
