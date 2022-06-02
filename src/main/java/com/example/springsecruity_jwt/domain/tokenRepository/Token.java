package com.example.springsecruity_jwt.domain.tokenRepository;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;


@Getter
@Entity
@NoArgsConstructor
@Table
public class Token {
    @Id
    @Column(name="username")
    private String username;

    @Column(nullable = false)
    private String token;

    @Builder
    public Token(String username, String token) {
        this.username = username;
        this.token = token;
    }
}
