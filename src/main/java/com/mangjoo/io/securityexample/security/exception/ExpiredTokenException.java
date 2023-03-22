package com.mangjoo.io.securityexample.security.exception;

import org.springframework.security.core.AuthenticationException;
public class ExpiredTokenException extends AuthenticationException {

    public ExpiredTokenException(String detail) {
        super(detail);
    }
}
