package com.example.springsecruity_jwt.service;

import com.example.springsecruity_jwt.domain.tokenRepository.TokenRepository;
import com.example.springsecruity_jwt.domain.userRepository.UsersRepository;
import com.example.springsecruity_jwt.web.dto.UserSaveRequestDto;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UsersRepository usersRepository;
    private final TokenRepository tokenRepository;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    @Transactional
    public void saveUser(UserSaveRequestDto userSaveRequestDto){
        usersRepository.save(userSaveRequestDto.toEntity(bCryptPasswordEncoder));
    }

//    @Transactional
//    public void saveToken(TokenSaveRequestDto tokenSaveRequestDto){
//        tokenRepository.save(tokenSaveRequestDto.toEntity());
//    }
}
