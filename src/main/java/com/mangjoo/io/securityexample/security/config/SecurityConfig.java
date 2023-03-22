package com.mangjoo.io.securityexample.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mangjoo.io.securityexample.security.filter.JwtAuthenticationFilter;
import com.mangjoo.io.securityexample.security.filter.LoginFilter;
import com.mangjoo.io.securityexample.security.handler.FailureHandler;
import com.mangjoo.io.securityexample.security.handler.SuccessHandler;
import com.mangjoo.io.securityexample.security.jwt.JwtService;
import com.mangjoo.io.securityexample.security.provider.JwtAuthenticationProvider;
import com.mangjoo.io.securityexample.security.provider.LoginProvider;
import com.mangjoo.io.securityexample.security.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final ObjectMapper objectMapper;
    private final SuccessHandler successHandler;
    private final FailureHandler failureHandler;
    private final JwtService jwtService;
    private final CustomUserDetailsService customUserDetailsService;
    private final LoginFilter loginFilter;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityFilterChain configure(
            HttpSecurity httpSecurity,
            LoginFilter loginFilter,
            JwtAuthenticationFilter jwtAuthenticationFilter
    ) throws Exception {
                httpSecurity.csrf().disable()
                .sessionManagement()
                .sessionCreationPolicy(STATELESS)
                .and()
                .authorizeHttpRequests()
                .requestMatchers("/api/v1/login").permitAll()
                .anyRequest().authenticated()
                .and()
                .authenticationProvider(new JwtAuthenticationProvider())
                .authenticationProvider(new LoginProvider(customUserDetailsService, passwordEncoder()))
                .addFilterBefore(loginFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return httpSecurity.build();
    }

    @Bean
    public LoginFilter loginFilter(AuthenticationManager authenticationManager) {
        LoginFilter loginFilter = new LoginFilter("/api/v1/login", objectMapper, successHandler, failureHandler);
        loginFilter.setAuthenticationManager(authenticationManager);
        return loginFilter;
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter("/api/v1/**", objectMapper, jwtService, failureHandler);
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
