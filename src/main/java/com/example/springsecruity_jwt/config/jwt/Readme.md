# Refresh Token & Access Token

## 통신 과정

![image](https://user-images.githubusercontent.com/40657327/171624379-321ab2aa-a465-4e57-aec1-0dca0e8bbdda.png)


## 구현 과정

1. 로그인 성공 시 Refresh, Access Token 발행 및 Refresh Token 저장

````java
// JwtAuthenticationFilter
...

@Override
protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

    PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

    String jwtToken = jwtTokenProvider.creatAccessToken(principalDetails.getUsername()); // accessToken 발급
    String refreshToken = jwtTokenProvider.createRefreshToken(); // refreshToken 발급

    Token token = Token.builder().username(principalDetails.getUsername()).token(refreshToken).build(); // refreshToken DB에 저장
    tokenRepository.save(token);

    response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken);
    response.addHeader(JwtProperties.REFRESH_HEADER_STRING, refreshToken);
    
    }

...
````


<details>
<summary>Token Repository 관련 코드</summary>
<div markdown="1">
    
````java
// Token

@Getter
@Entity
@NoArgsConstructor
@Table
public class Token {
    @Id
    @Column(name="username")
    private String username;

    @Column(nullable = false)
    private String token;

    @Builder
    public Token(String username, String token) {
        this.username = username;
        this.token = token;
    }
}

````

````java
// TokenRepository

public interface TokenRepository extends JpaRepository<Token, String> {
    public Token findByUsername(String username);
}
````

</div>
</details>

2. Refresh Token을 통해 Access Token 처리 과정
>  1️⃣  Access Token이 만료된 경우, Access Token이 만료되었음을 클라이언트에게 알림    
>  2️⃣  클라이언트로부터 AccessToken, Refresh Token을 가져옴   
>  3️⃣  클라이언트에서 가져온 Refresh Token과 DB에 존재하는 해당 유저의 Refresh Token이 같은지 비교     
>  4️⃣  클라이언트에서 가져온 Refresh Token의 유효성 검사   
>  5️⃣  Access Token 재발급 후 클라이언트로 전송


````java
// AuthorizationFilter

@Override
protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
    String jwtHeader = jwtTokenProvider.resolveJwtToken(request);

    ...

    String accessToken = jwtHeader.replace(JwtProperties.TOKEN_PREFIX, ""); // Access Token만 추출

    if (jwtTokenProvider.tokenValid(accessToken)) { // AccessToken 유효성(만료시간) 검사
    String username = jwtTokenProvider.getVerifyToken(accessToken).getClaim("username").asString();

        if (username != null && !username.equals("")) {
            User user = userRepository.findByUsername(username);
            PrincipalDetails principalDetails = new PrincipalDetails(user);
        
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails.getUsername(), null, principalDetails.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication); // 인증된 사용자 정보를 세션에 주입
            chain.doFilter(request, response);
        
        }
        else{
            System.out.println("[ERR] ACCESS TOKEN 사용자 정보 에러");
            ...
            return;
        }
    
    }
    else{ // Access Token 만료된 경우
        System.out.println("[WARN] Expired Access Token");

        // 클라이언트가 Refresh Token을 갖고 요청한 경우
        if(request.getHeader(JwtProperties.REFRESH_HEADER_STRING) != null){
    
            // Refresh Token 유효성(만료시간) 검사
            String refresh = request.getHeader(JwtProperties.REFRESH_HEADER_STRING);
            String username = JWT.decode(accessToken).getClaim("username").asString(); // Access Token에서 username만 추출
            
            // DB의 Refresh와 클라이언트에서 받은 Refresh 비교
            if(refresh.equals(tokenRepository.findByUsername(username).getToken())){
                System.out.println("[SUCCESS] 정상적인 Refresh Token");
            
                if(jwtTokenProvider.tokenValid(refresh)){ // refresh token 만료 여부 확인
                String reissueAccessToken = jwtTokenProvider.creatAccessToken(username); // 새로운 Access Token 발행
                response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + reissueAccessToken); // 클라이언트로 전송
                }
                else{
                    System.out.println("[ERR] Refresh Token 만료됨, 재로그인 요청");
                    tokenRepository.deleteById(username); // 해당 user의 Refresh Token 삭제 
                    ...
                    return;
                }
                
            }
            else{
                System.out.println("[ERR] 비정상적인 Refresh Token, 재로그인 요청");
                tokenRepository.deleteById(username); // DB에 존재하는 refresh token 삭제
                ...
                return;
            }

        }
    
        else{
            // 클라이언트에게 Access Token이 만료됨을 응답
            ...
            return;
        }

    }


}
````

<details>
<summary>JwtProvider 클래스</summary>
<div markdown="1">

````java

@Component // 개발자가 직접 작성한 class를 Bean으로 등록하기 위한 어노테이션
@NoArgsConstructor
public class JwtTokenProvider {

    public String creatAccessToken(String username){ // AccessToken 생성함수
        return JWT.create()
            .withSubject("jwt_token")
            .withExpiresAt(new Date(System.currentTimeMillis() + 만료시간)
            .withClaim("username", username)
            .sign(Algorithm.HMAC256("secretKey"));
    }
    
    public String createRefreshToken(){ // Refresh Token 생성 함수
        return JWT.create()
            .withExpiresAt(new Date(System.currentTimeMillis() + 만료시간) )
            .sign(Algorithm.HMAC256("secretKey"));
    }

    public String resolveJwtToken(HttpServletRequest request){ // Access Token 값 추출
        return request.getHeader("Authorization");
    }

    public DecodedJWT getVerifyToken(String token){ // 토큰 검증
        return JWT.require(Algorithm.HMAC256("secretKey")).build().verify(token);
    }
    
    public boolean tokenValid(String token){ // Token 유효성 확인
        try{
            // 만료시간.before(현재시간)
            // 만료시간 < 현재시간 : true
            // 만료시간 > 현재시간 : false
            return !getVerifyToken(token).getExpiresAt().before(new Date()); 
        }catch (Exception e){
            return false;
        }
    }
}

````

</div>
</details>
