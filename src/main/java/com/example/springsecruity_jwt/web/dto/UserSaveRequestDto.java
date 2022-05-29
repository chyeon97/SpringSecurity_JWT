package com.example.springsecruity_jwt.web.dto;

import com.example.springsecruity_jwt.domain.userRepository.Users;
import lombok.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Getter
@Data
@NoArgsConstructor
public class UserSaveRequestDto {
    private String username;
    private String password;
    private String role;

    @Builder
    public UserSaveRequestDto(String username, String password, String role){
        this.username=username;
        this.password=password;
        this.role=role;
    }


    // User 엔티티 클래스에 User 객체 넣기
    public Users toEntity(BCryptPasswordEncoder bCryptPasswordEncoder){
        return Users.builder().username(username).password(bCryptPasswordEncoder.encode(password)).roles(role).build();
    }
}
