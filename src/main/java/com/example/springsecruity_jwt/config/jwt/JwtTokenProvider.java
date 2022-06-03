package com.example.springsecruity_jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.*;
import org.springframework.stereotype.Component;
import javax.servlet.http.HttpServletRequest;
import java.util.Date;

@Component
@Data
@NoArgsConstructor
public class JwtTokenProvider {

    public String creatAccessToken(String username){ // AccessToken 생성함수
        return JWT.create()
            .withSubject("jwt_token")
            .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.ACCESS_EXPIRATION_TIME))
            .withClaim("username", username)
            .sign(Algorithm.HMAC256(JwtProperties.SECRET));
    }
    public String createRefreshToken(){ // Refresh Token 생성 함수
        return JWT.create()
            .withExpiresAt(new Date(System.currentTimeMillis()  +JwtProperties.REFRESH_EXPIRATION_TIME) )
            .sign(Algorithm.HMAC256(JwtProperties.SECRET));
    }

    public String resolveJwtToken(HttpServletRequest request){ // Access Token 값 추출
        return request.getHeader(JwtProperties.HEADER_STRING);
    }

    public DecodedJWT getVerifyToken(String token){ // 토큰 검증
        return JWT.require(Algorithm.HMAC256(JwtProperties.SECRET)).build().verify(token);
    }

    public boolean tokenValid(String token){ // Refresh Token 유효성 확인
        try{
            return !getVerifyToken(token).getExpiresAt().before(new Date());
        }catch (Exception e){
            return false;
        }
    }



}
