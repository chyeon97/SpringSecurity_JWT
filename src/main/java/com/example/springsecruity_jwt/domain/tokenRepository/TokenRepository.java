package com.example.springsecruity_jwt.domain.tokenRepository;

import org.springframework.data.jpa.repository.JpaRepository;

public interface TokenRepository extends JpaRepository<Token, String> {
    public Token findByUsername(String username);
}
