package com.portfolio.tech_stack.auth.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "users", indexes = {
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

    @Column(nullable = false, unique = true)
    private String email;

    @Column  // nullable - OAuth2 사용자는 비밀번호 없을 수 있음
    private String password;

    @Column(nullable = false, length = 100)
    private String name;

    @Column(length = 500)
    private String profileImageUrl;

    // 최초 가입 provider (불변)
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 50)
    private AuthProvider primaryProvider;

    // 연결된 모든 providers ("DEFAULT,GOOGLE,GITHUB")
    @Column(length = 255)
    @Builder.Default
    private String linkedProviders = "";

    // Provider별 ID 저장 (형태: "GOOGLE:123,GITHUB:456")
    @Column(length = 1000, columnDefinition = "TEXT")
    private String providerIds;

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
