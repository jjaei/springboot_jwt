package com.cos.jwt.filter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

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
        // 2. 정상인지 로그인 시도를 해본다.
        // 3. authenticationManager로 로그인 시도를 하면 PrincipalDetailsService가 호출된다.
        // 4. 그럼 loadByUsername이 자동으로 실행된다.

        // 5. PrincipalDetails를 세션에 담고(권한 관리를 위해)
        // 6. JWT 토큰을 만들어서 응답한다.
        return super.attemptAuthentication(request, response);
    }
}
