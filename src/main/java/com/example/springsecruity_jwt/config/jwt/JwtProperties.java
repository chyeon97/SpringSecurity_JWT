package com.example.springsecruity_jwt.config.jwt;

public interface JwtProperties {
    String SECRET = "JWT_TOKEN"; // 서버만 아는 비밀 키
    int EXPIRATION_TIME = 600000; // 10분
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";
 }
