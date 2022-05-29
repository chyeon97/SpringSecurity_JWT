package com.example.springsecruity_jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.springsecruity_jwt.config.auth.PrincipalDetails;
import com.example.springsecruity_jwt.domain.userRepository.Users;
import com.example.springsecruity_jwt.domain.userRepository.UsersRepository;
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

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UsersRepository usersRepository) {
        super(authenticationManager);
        this.usersRepository = usersRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String jwtHeader = request.getHeader(JwtProperties.HEADER_STRING);

        if(jwtHeader == null || !jwtHeader.startsWith(JwtProperties.TOKEN_PREFIX)){
            chain.doFilter(request,response);
            return;
        }

        String jwtToken = jwtHeader.replace(JwtProperties.TOKEN_PREFIX, "");
        String username = JWT.require(Algorithm.HMAC256(JwtProperties.SECRET)).build().verify(jwtToken).getClaim("username").asString();

        if(username != null && !username.equals("")){
            Users user = usersRepository.findByUsername(username);
            PrincipalDetails principalDetails = new PrincipalDetails(user);

            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails.getUsername(), null, principalDetails.getAuthorities() );
            SecurityContextHolder.getContext().setAuthentication(authentication);

            chain.doFilter(request,response);
        }
    }
}
