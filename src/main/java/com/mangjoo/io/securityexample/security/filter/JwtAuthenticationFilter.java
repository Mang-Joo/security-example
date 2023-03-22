package com.mangjoo.io.securityexample.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mangjoo.io.securityexample.security.handler.FailureHandler;
import com.mangjoo.io.securityexample.security.jwt.JwtAuthenticationToken;
import com.mangjoo.io.securityexample.security.jwt.JwtService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import java.io.IOException;

@Order(1)
public class JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    private final ObjectMapper objectMapper;
    private final JwtService jwtService;

    private final FailureHandler failureHandler;

    public JwtAuthenticationFilter(String defaultFilterProcessesUrl, ObjectMapper objectMapper, JwtService jwtService, FailureHandler failureHandler) {
        super(defaultFilterProcessesUrl);
        this.objectMapper = objectMapper;
        this.jwtService = jwtService;
        this.failureHandler = failureHandler;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        if (!request.getContentType().equals("application/json")) {
            throw new IllegalArgumentException("Content type must be application/json");
        }

        String jwt = request.getHeader("Authorization");

        if (jwt == null) {
            throw new IllegalArgumentException("Authorization header must be provided");
        }

        Claims claims = jwtService.parseJwt(jwt);

        return getAuthenticationManager().authenticate(new JwtAuthenticationToken(claims));
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authResult);
        SecurityContextHolder.setContext(context);
        chain.doFilter(request, response);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException {
        SecurityContextHolder.clearContext();
        failureHandler.onAuthenticationFailure(request, response, failed);
    }
}
