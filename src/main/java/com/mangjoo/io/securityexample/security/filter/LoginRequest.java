package com.mangjoo.io.securityexample.security.filter;

public record LoginRequest(
        String username,
        String password
) {
}
