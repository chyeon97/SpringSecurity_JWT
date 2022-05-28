package com.example.springsecruity_jwt.web.dto;

import com.example.springsecruity_jwt.domain.userRepository.Users;
import com.example.springsecruity_jwt.web.model.User;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;

@Getter
@NoArgsConstructor
public class UserSaveRequestDto {
    private User user = new User();

    @Builder
    public UserSaveRequestDto(String username, String password, String role){
        System.out.println("username: " + username);
        user.setUsername(username);
        user.setPassword(password);
        user.setRole(role);
    }


    // User 엔티티 클래스에 User 객체 넣기
    public Users toEntity(){
        return Users.builder().username(user.getUsername()).password(user.getPassword()).roles(user.getRole()).build();
    }
}
