package com.cos.jwt.config;

import com.cos.jwt.filter.MyFilter3;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.addFilterBefore(new MyFilter3(), BasicAuthenticationFilter.class);
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션 사용하지 않음
                .and()
                .addFilter(corsFilter)  // @CrossOrigin(인증X), 시큐리티 필터에 등록 인증(O)
                .formLogin().disable()
                .httpBasic().disable()
                .authorizeHttpRequests()
                .requestMatchers("/api/v1/user/**")
                .hasAnyRole("USER", "MANAGER", "ADMIN")
                .requestMatchers("/api/v1/manger/**")
                .hasAnyRole("MANAGER", "ADMIN")
                .requestMatchers("/api/v1/admin/**")
                .hasRole("ADMIN")
                .anyRequest().permitAll();
        return http.build();
    }
}
