package com.example.springsecruity_jwt.domain.userRepository;

import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Getter
@NoArgsConstructor
@Entity
@Data // tostring 테스트용
@Table(name= "USER_TEST")
public class Users {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    private Long id;

    @Column(nullable = false, length = 30)
    private String username;
    @Column(nullable = false)
    private String password;

    @Column(nullable = false, length = 50)
    private String roles; // user, admin

    @Builder
    public Users(Long id, String username, String password, String roles){
        this.id =id;
        this.username = username;
        this.password = password;
        this.roles = roles;
    }

    public List<String> getRoleList(){
        if(this.roles.length()>0){
            return Arrays.asList(this.roles.split(","));
        }
        return new ArrayList<>();
    }
}
