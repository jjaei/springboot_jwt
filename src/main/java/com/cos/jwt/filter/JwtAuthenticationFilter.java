package com.cos.jwt.filter;

import com.cos.jwt.auth.PrincipalDetails;
import com.cos.jwt.entity.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter
// /login 요청 시 username, password POST로 전송하면 필터가 동작됨.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // 로그인 요청을 하면 로그인 시도를 위해 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter : 로그인 시도 중");

        // 1. username, password 받아서
        try {
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // 이게 실행될 때 PrincipalDetailsService에 loadUserByUsername()이 실행된다.
            // 정상이면 authentication 이 리턴됨.
            // db에 있는 username과 password가 일치한다.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료: " +principalDetails.getUser().getUsername());  // 값이 있다는 것은 정상 로그인
            // authentication 객체가 session 영역에 저장됨. -> 로그인이 되었다는 의미
            return authentication;
        } catch (Exception e) {
            e.printStackTrace();
        }
        // 2. 정상인지 로그인 시도를 해본다.
        // 3. authenticationManager로 로그인 시도를 하면 PrincipalDetailsService가 호출된다.
        // 4. 그럼 loadByUsername이 자동으로 실행된다.

        // 5. PrincipalDetails를 세션에 담고(권한 관리를 위해)
        // 6. JWT 토큰을 만들어서 응답한다.
        return null;
    }

    // attempAuthentication 실행 후 인증이 정상적으로 되면 이 함수가 실행된다.
    // jWT 토큰을 만들어서 request를 요청한 사용자에게 jWT 토큰을 response 해주면 됨.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨, 인증이 완료되었다는 뜻" );
        super.successfulAuthentication(request, response, chain, authResult);
    }
}
