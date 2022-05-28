package com.example.springsecruity_jwt.service;

import com.example.springsecruity_jwt.domain.userRepository.UsersRepository;
import com.example.springsecruity_jwt.web.dto.UserSaveRequestDto;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UsersRepository usersRepository;

    @Transactional
    public void saveUser(UserSaveRequestDto userSaveRequestDto){
        usersRepository.save(userSaveRequestDto.toEntity());
    }
}
