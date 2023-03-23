package com.mangjoo.io.securityexample.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mangjoo.io.securityexample.security.filter.JwtAuthenticationFilter;
import com.mangjoo.io.securityexample.security.filter.LoginFilter;
import com.mangjoo.io.securityexample.security.handler.FailureHandler;
import com.mangjoo.io.securityexample.security.handler.SuccessHandler;
import com.mangjoo.io.securityexample.security.provider.JwtAuthenticationProvider;
import com.mangjoo.io.securityexample.security.provider.LoginProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.List;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final ObjectMapper objectMapper;
    private final SuccessHandler successHandler;
    private final FailureHandler failureHandler;
    private final LoginProvider loginProvider;
    private final JwtAuthenticationProvider jwtAuthenticationProvider;

    @Bean
    public SecurityFilterChain configure(
            HttpSecurity httpSecurity,
            AuthenticationManager authenticationManager
    ) throws Exception {
        httpSecurity.csrf().disable()
                .sessionManagement()
                .sessionCreationPolicy(STATELESS)
                .and()
                .authorizeHttpRequests()
                .requestMatchers("/api/v1/login").permitAll()
//                .requestMatchers("/api/v1/user/**")
//                .hasRole(USER.name())
                .anyRequest()
                .authenticated()
                .and()
                .addFilterBefore(loginFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtAuthenticationFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class);

        httpSecurity
                .authenticationProvider(loginProvider)
                .authenticationProvider(jwtAuthenticationProvider);

        return httpSecurity.build();
    }

    private LoginFilter loginFilter(AuthenticationManager authenticationManager) {
        LoginFilter loginFilter = new LoginFilter("/api/v1/login", objectMapper, successHandler, failureHandler);
        loginFilter.setAuthenticationManager(authenticationManager);
        return loginFilter;
    }

    private JwtAuthenticationFilter jwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter("/api/v1/user/**", failureHandler);
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(List.of(jwtAuthenticationProvider, loginProvider));
    }
}
