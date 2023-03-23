package com.mangjoo.io.securityexample.security.filter;

import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mangjoo.io.securityexample.security.handler.FailureHandler;
import com.mangjoo.io.securityexample.security.handler.SuccessHandler;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import java.io.IOException;

@Slf4j
public class LoginFilter extends AbstractAuthenticationProcessingFilter {

    private final ObjectMapper objectMapper;

    private final SuccessHandler successHandler;

    private final FailureHandler failureHandler;

    public LoginFilter(String defaultFilterProcessesUrl, ObjectMapper objectMapper, SuccessHandler successHandler, FailureHandler failureHandler) {
        super(defaultFilterProcessesUrl);
        this.objectMapper = objectMapper;
        this.successHandler = successHandler;
        this.failureHandler = failureHandler;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if (!request.getContentType().equals("application/json")) {
            throw new IllegalArgumentException("Content type must be application/json");
        }
        if (!request.getMethod().equals(HttpMethod.POST.name())) {
            throw new IllegalArgumentException("must be POST Method");
        }
        //pricipal: 사용자 식별자
        //credentials: 암호화 되어야 하는 애
        try {
            LoginRequest loginRequest = objectMapper.readValue(request.getReader(), LoginRequest.class);
            log.info("LoginRequest: {}", loginRequest);
            log.info("test {}", getAuthenticationManager());
            return getAuthenticationManager().authenticate(new UsernamePasswordAuthenticationToken(loginRequest.username(), loginRequest.password()));
        } catch (DatabindException e) {
            throw new IllegalArgumentException("json parse error");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException {
        //Success Handler
        successHandler.onAuthenticationSuccess(request, response, authResult);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException {
        //FailureHandler Handler
        failureHandler.onAuthenticationFailure(request, response, failed);
    }
}

