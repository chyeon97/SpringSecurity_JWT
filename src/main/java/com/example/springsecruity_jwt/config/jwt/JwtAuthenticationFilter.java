package com.example.springsecruity_jwt.config.jwt;

import com.example.springsecruity_jwt.config.auth.PrincipalDetails;
import com.example.springsecruity_jwt.constants.StatusCode;
import com.example.springsecruity_jwt.domain.tokenRepository.Token;
import com.example.springsecruity_jwt.domain.tokenRepository.TokenRepository;
import com.example.springsecruity_jwt.domain.userRepository.Users;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final TokenRepository tokenRepository;
    private  final JwtTokenProvider jwtTokenProvider;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        try {
            ObjectMapper om = new ObjectMapper();
            Users user = om.readValue(request.getInputStream(), Users.class);

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
            Authentication authentication = authenticationManager.authenticate(authenticationToken);
            return authentication;

        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }



    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = jwtTokenProvider.creatAccessToken(principalDetails.getUsername()); // accessToken 발급
        String refreshToken = jwtTokenProvider.createRefreshToken(); // refreshToken 발급

        Token token = Token.builder().username(principalDetails.getUsername()).token(refreshToken).build(); // refreshToken DB에 저장
        tokenRepository.save(token);

        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken);
        response.addHeader(JwtProperties.REFRESH_HEADER_STRING, refreshToken);
    }


    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        StatusCode statusCode = new StatusCode("로그인 실패", 1);
        ObjectMapper om = new ObjectMapper();
        String result = om.writeValueAsString(statusCode);
        response.getWriter().write(result);
    }
}
