package com.portfolio.tech_stack.auth.repository;

import com.portfolio.tech_stack.auth.entity.AuthProvider;
import com.portfolio.tech_stack.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);
    Optional<User> findByProviderAndProviderId(AuthProvider provider, String providerId);
    Boolean existsByProviderAndProviderId(AuthProvider provider, String providerId);
}
