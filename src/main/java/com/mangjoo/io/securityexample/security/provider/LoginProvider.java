package com.mangjoo.io.securityexample.security.provider;

import com.mangjoo.io.securityexample.application.persistence.MemberEntity;
import com.mangjoo.io.securityexample.security.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class LoginProvider implements AuthenticationProvider {

    private final CustomUserDetailsService customUserDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();

        MemberEntity memberEntity = customUserDetailsService.loadUserByUsername(username);

        if (!passwordEncoder.matches(password, memberEntity.getPassword())) {
            throw new BadCredentialsException("password not match");
        }

        List<GrantedAuthority> authorities = List.of(
                new SimpleGrantedAuthority(memberEntity.getRole().name())
        );

        return new UsernamePasswordAuthenticationToken(memberEntity.getId(), null, authorities);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

