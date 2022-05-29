package com.example.springsecruity_jwt.config;


import com.example.springsecruity_jwt.config.jwt.JwtAuthenticationFilter;
import com.example.springsecruity_jwt.config.jwt.JwtAuthorizationFilter;
import com.example.springsecruity_jwt.domain.userRepository.UsersRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UsersRepository usersRepository;
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .formLogin().disable()
            .httpBasic().disable()
            .addFilter(new JwtAuthenticationFilter(authenticationManager()))
            .addFilter(new JwtAuthorizationFilter(authenticationManager(), usersRepository))
            .authorizeRequests()
            .antMatchers("/api/user/**").access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
            .antMatchers("/api/admin/**").access("hasRole('ROLE_ADMIN')")
            .anyRequest().permitAll();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
