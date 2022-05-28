# 스프링 시큐리티와 JWT

## 📁 디렉토리 구조

| 폴더 / 파일 | 설명                 | 세부 폴더                  |
|---------|--------------------|------------------------|
| web     | 외부 요청/응답에 대한 전반적인 영역 | model, dto, controller |
| service | 트랜잭션(@Transactional) | -                      |
| domain  | 데이터 저장소에 접근하는 영역   | -                      |
| config  | 시큐리티 설정         | - |


## 🛹 전체적인 흐름
`JWT 토큰 발행을 위한 흐름`
> 로그인 요청 > CORS 필터 > 유효한(DB에 존재하는) 사용자인지 확인 > JWT 토큰 발행 > HTTP 헤더에 JWT 토큰을 포함하여 클라언트로 전송

`로그인 이후 사용자 인증의 흐름`
> 클라이언트 요청 > CORS 필터 > HTTP 헤더에 JWT 토큰이 존재하는지 확인 > 유효한(DB에 존재하는) 사용자인지 확인 > 시큐리티 세션 공간에 authentication 객체를 저장 > 다음 시큐리티 필터로 이동

## 🔐 SpringSecurity

> 스프링 기반의 어플리케이션의 보안을 담당하는 스프링 하위 프레임 워크

### 기본 용어

 ● `Principal` : 보호된 리소스에 접근하는 대상 (접근 주체)    
 ● `Authentication` : 접근 주체가 누구인지, 어플리케이션의 작업을 수행해도 되는 주체인지 확인하는 과정   
 ● `Authorization` : 해당 리소스에 대한 접근 가능한 권한을 가지고 있는지 확인하는 과정(인증 이후 수행)

### 구조 및 필터

![img.png](img.png)

| 필터                                     | 설명                                                                                         |
|----------------------------------------|--------------------------------------------------------------------------------------------|
| SecurityContextPersistenceFilter       | SecurityContextRepository에서 SecurityContext를 로드하고 저장하는 일을 담당                               |
| LogoutFilter                           | 로그아웃 URL로 지정된 가상URL("/logout)에 대해 요청을 감시하고 매칭되는 요청이 있으면 사용자를 로그아웃 시킴                       |
| * UsernamePasswordAuthenticationFilter | 사용자명(username), 비밀번호(password)로 이뤄진 인증에 사용하는 가상URL("/login") 요청을 감시하고 요청이 있으면 사용자의 인증을 진행함 |
| DefaultLoginPageGenerationFilter       | Form기반, OpenID 기반 인증에 사용하는 가상URL에 대한 요청을 감시하고 로그인 폼 기능을 수행하는데 필요한 HTML을 생성함                |
| * BasicAuthenticationFilter            | HTTP 기본 인증 헤더를 감시하고 이를 처리함                                                                 |
| RequestCacheAwareFilter                | 로그인 성공 이후, 인증 요청에 의해 가로채어진 사용자의 원래 요청을 재구성하는 역할                                            |
| AnonymousAuthenticationFilter          | 이 필터가 호출되는 시점까지 사용자 인증을 받지 못하면, 요청 관련 인증 토큰에서 사용자는 익명 사용자로 나타나게 됨                          |
| SessionMangementFilter                 | 인증된 주체를 바탕으로 세션 추적을 처리해 단일 주체와 관련한 모든 세션들이 트래킹되도록 도움                                       |
| ExceptionalTranslationFilter           | 보호된 요청을 처리하는 동안 발생할 수 있는 기대한 예외의 기본 라우팅과 위임을 처리함                                           |
| FilterSecurityInterceptor              | 권한 부여와 관련한 결정을 AccessDecisionManger에게 위임해 권한 부여 결정 및 접근 제어 결정을 쉽게 만들어 줌                    |


### 📍 사용법

1. dependency 추가

```
dependencies {
	compile 'org.springframework.security:spring-security-web:4.2.2.RELEASE'
	compile 'org.springframework.security:spring-security-config:4.2.2.RELEASE'
}
```

2. Configuration 설정

````java
@Configuration // 자바 기반의 설정 파일로 인식
@EnableWebSecurity // spring security filter chain에 자동으로 등록 됨
public class SecurityConfig extends WebSecurityConfigAdapter{
    // configure메서드를 오버라이딩하여 사용하고자 하는 시큐리티 규칙을 작성함
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable(); // csrf 보안 설정 비활성화
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션 사용 비활성화
            .and()
            .addFilter(corsFilter) // CORS 해제 정책 필터 등록
            .formLogin().disable() // formLogin 요청 방식 비활성화
            .httpBasic().disable() // http basic 요청 방식 비활성화
            .addFilter(new JwtAuthenticationFilter(authenticationManager())) // 사용자 인증 확인 및 JWT 토큰 발행하는 필터 추가
            .addFilter(new JwtAuthorizationFilter(authenticationManager(),userRepository)) // JWT 토큰 유효성 검사 및 시큐리티 세션에 Authentication 객체 저장하는 필터 추가
            .authorizeRequests() // 보호된 리소스 URI에 접근할 수 있는 권한을 설정
            // user라는 Role을 가진 Principal에 대한 인가 설정
            .antMatchers("/api/v1/user/**").access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER')  or hasRole('ROLE_ADMIN')")
            .antMatchers("/api/v1/manager/**").access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
            .antMatchers("/api/v1/admin/**").access("hasRole('ROLE_ADMIN')")
            .anyRequest().permitAll();
    }
}
````

3. UserDetails 구현

> Spring Security에서 사용자 정보를 담는 인터페이스    
> 즉, ︎ Spring Security에서 구현한 클래스를 사용자 정보로 인식하고 인증 작업을 한다.

```java
package com.example.jwtstart.auth;
//...
@AllArgsConstructor
public class PrincipalDetails implements UserDetails {
    
    private User user; 
    
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() { // 해당 유저의 권한을 리턴하는 곳
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        ...
        return authorities;
    }

    @Override
    public String getPassword() { // 해당 유저의 비밀번호 리턴
        return user.getPassword();
    } 

    @Override
    public String getUsername() { // 해당 유저의 이름을 리턴
        return user.getUsername();
    } 

    @Override
    public boolean isAccountNonExpired() { // 해당 계정이 만료되지 않았는지 리턴(true: 만료 안됨)
        return true;
    } 

    @Override
    public boolean isAccountNonLocked() { // 해당 계정이 잠겨있지 않았는지 리턴(true: 잠기지 않음)
        return true;
    } 
    @Override
    public boolean isCredentialsNonExpired() { // 해당 계정의 비밀번호가 만료되지 않았는 리턴(true: 만료 안됨)
        return true;
    } 

    @Override
    public boolean isEnabled() { // 해당 계정이 활성화(사용가능)인 지 리턴 (true: 활성화)
        return true;
    }
}

```


4. UserDetailsService 구현
> DB에서 유저 정보를 가져오는 역할   
> 즉, loadUserByUsername()에서 DB의 유저 정보를 가져와서 구현한 UserService 형으로 사용자 정보를 반환하는 곳

```java
@Service
@RequiredArgsConstructor
public class PrincipleDetailsService implements UserDetailsService {
    private final UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User userEntity = userRepository.findByUsername(username);
         return new PrincipalDetails(userEntity);
    }
}
```

