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

        if (jwtTokenProvider.tokenValid(accessToken)) { // AccessToken ?????????(????????????) ??????
            String username = jwtTokenProvider.getVerifyToken(accessToken).getClaim("username").asString();

            if (username != null && !username.equals("")) {
                Users user = usersRepository.findByUsername(username);
                PrincipalDetails principalDetails = new PrincipalDetails(user);

                Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails.getUsername(), null, principalDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authentication);

                chain.doFilter(request, response);
            }else{
                System.out.println("[ERR] ACCESS TOKEN ????????? ?????? ??????");
                statusCode.setResCode(1); statusCode.setResMsg("[ERR] ACCESS TOKEN ????????? ?????? ??????");
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
                    System.out.println("[SUCCESS] ???????????? Refresh Token");

                    if(jwtTokenProvider.tokenValid(refresh)){ // refresh token ?????? ?????? ??????
                        String reissueAccessToken = jwtTokenProvider.creatAccessToken(username);
                        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + reissueAccessToken);
                    }else{
                        System.out.println("[ERR] Refresh Token ?????????, ???????????? ??????");
                        tokenRepository.deleteById(username);
                        statusCode.setResCode(2); statusCode.setResMsg("????????? Refresh Token");
                        String result = om.writeValueAsString(statusCode);
                        response.getWriter().write(result);
                        return;
                    }
                }else{
                    System.out.println("[ERR] ??????????????? Refresh Token");
                    tokenRepository.deleteById(username); // DB??? ???????????? refresh token ??????
                    statusCode.setResCode(2); statusCode.setResMsg("??????????????? Refresh Token");
                    String result = om.writeValueAsString(statusCode);
                    response.getWriter().write(result);
                    return;
                }

            }else{
                statusCode.setResCode(1); statusCode.setResMsg("Access Token ?????????");
                String result = om.writeValueAsString(statusCode);
                response.getWriter().write(result);
                return;
            }

        }
    }

    }



