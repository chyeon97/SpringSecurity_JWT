package com.example.springsecruity_jwt.web.controller;

import com.example.springsecruity_jwt.domain.userRepository.UsersRepository;
import com.example.springsecruity_jwt.web.dto.UserSaveRequestDto;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;

import static org.junit.Assert.*;
import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class UserApiControllerTest {
    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate testRestTemplate;

    @Autowired
    private UsersRepository usersRepository;

    @After
    public void cleanup(){
        usersRepository.deleteAll();
    }

    @Test
    public void saveUserTest() throws Exception{
        // given
        String username = "박채연";
        String password = "test123";
        String roles = "ROLE_ADMIN";

        UserSaveRequestDto requestDto = UserSaveRequestDto.builder().username(username).password(password).role(roles).build();
        requestDto.toString();
        String url = "http://localhost:"+port +"/signup";

        // when
        ResponseEntity<Void> responseEntity = testRestTemplate.postForEntity(url, requestDto, Void.class);

        // then
        assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

}