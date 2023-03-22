package com.mangjoo.io.securityexample.security.exception;

import org.springframework.security.core.AuthenticationException;

public class JwtSignatureException extends AuthenticationException {
    public JwtSignatureException(String msg) {
        super(msg);
    }
}
