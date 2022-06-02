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
        Users userEntity = usersRepository.findByUsername(username);
        if(userEntity == null){
            System.out.println("[Err] Unknown User");
        }
        return new PrincipalDetails(userEntity);
    }
}
