package com.example.springsecruity_jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.example.springsecruity_jwt.config.auth.PrincipalDetails;
import com.example.springsecruity_jwt.constants.StatusCode;
import com.example.springsecruity_jwt.domain.tokenRepository.TokenRepository;
import com.example.springsecruity_jwt.domain.userRepository.Users;
import com.example.springsecruity_jwt.domain.userRepository.UsersRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private  UsersRepository usersRepository;
    private  TokenRepository tokenRepository;

    private JwtTokenProvider jwtTokenProvider;

    private ObjectMapper om = new ObjectMapper();
    private StatusCode statusCode = new StatusCode();

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UsersRepository usersRepository, TokenRepository tokenRepository, JwtTokenProvider jwtTokenProvider) {
        super(authenticationManager);
        this.usersRepository = usersRepository;
        this.tokenRepository = tokenRepository;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        String jwtHeader = jwtTokenProvider.resolveJwtToken(request);

        if (jwtHeader == null || !jwtHeader.startsWith(JwtProperties.TOKEN_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }

        String accessToken = jwtHeader.replace(JwtProperties.TOKEN_PREFIX, "");

        if (jwtTokenProvider.tokenValid(accessToken)) { // AccessToken 유효성(만료시간) 검사
            String username = jwtTokenProvider.getVerifyToken(accessToken).getClaim("username").asString();

            if (username != null && !username.equals("")) {
                Users user = usersRepository.findByUsername(username);
                PrincipalDetails principalDetails = new PrincipalDetails(user);

                Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails.getUsername(), null, principalDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authentication);

                chain.doFilter(request, response);
            }else{
                System.out.println("[ERR] ACCESS TOKEN 사용자 정보 에러");
                statusCode.setResCode(1); statusCode.setResMsg("[ERR] ACCESS TOKEN 사용자 정보 에러");
                String result = om.writeValueAsString(statusCode);
                response.getWriter().write(result);
                return;
            }
        }
        else{

            System.out.println("[WARN] Expired Access Token");


            if(request.getHeader(JwtProperties.REFRESH_HEADER_STRING) != null){

                String refresh = request.getHeader(JwtProperties.REFRESH_HEADER_STRING);
                System.out.println("refresh = " + refresh);
                String username = JWT.decode(accessToken).getClaim("username").asString();

                if(refresh.equals(tokenRepository.findByUsername(username).getToken())){
                    System.out.println("[SUCCESS] 정상적인 Refresh Token");

                    if(jwtTokenProvider.tokenValid(refresh)){ // refresh token 만료 여부 확인
                        String reissueAccessToken = jwtTokenProvider.creatAccessToken(username);
                        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + reissueAccessToken);
                    }else{
                        System.out.println("[ERR] Refresh Token 만료됨, 재로그인 요청");
                        tokenRepository.deleteById(username);
                        statusCode.setResCode(2); statusCode.setResMsg("만료된 Refresh Token");
                        String result = om.writeValueAsString(statusCode);
                        response.getWriter().write(result);
                        return;
                    }
                }else{
                    System.out.println("[ERR] 비정상적인 Refresh Token");
                    tokenRepository.deleteById(username); // DB에 존재하는 refresh token 삭제
                    statusCode.setResCode(2); statusCode.setResMsg("비정상적인 Refresh Token");
                    String result = om.writeValueAsString(statusCode);
                    response.getWriter().write(result);
                    return;
                }

            }else{
                statusCode.setResCode(1); statusCode.setResMsg("Access Token 만료됨");
                String result = om.writeValueAsString(statusCode);
                response.getWriter().write(result);
                return;
            }

        }
    }

    }



