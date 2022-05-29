package com.example.springsecruity_jwt.config.auth;

import com.example.springsecruity_jwt.domain.userRepository.Users;
import com.example.springsecruity_jwt.domain.userRepository.UsersRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UsersRepository usersRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("username: " + username);
        Users userEntity = usersRepository.findByUsername(username);

        System.out.println("Users: " + userEntity.toString());
        return new PrincipalDetails(userEntity);
    }
}
