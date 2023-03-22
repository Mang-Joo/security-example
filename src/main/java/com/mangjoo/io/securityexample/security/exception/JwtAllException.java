package com.mangjoo.io.securityexample.security.exception;

import org.springframework.security.core.AuthenticationException;

public class JwtAllException extends AuthenticationException {
    public JwtAllException(String message) {
        super(message);
    }
}
