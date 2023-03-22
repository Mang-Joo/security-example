package com.mangjoo.io.securityexample.security.provider;

import com.mangjoo.io.securityexample.application.persistence.MemberEntity;
import com.mangjoo.io.securityexample.application.persistence.Role;
import com.mangjoo.io.securityexample.security.service.CustomUserDetailsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
class LoginProviderTest {

    LoginProvider loginProvider;

    @Mock
    CustomUserDetailsService customUserDetailsService;

    PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @BeforeEach
    void setup() {
        loginProvider = new LoginProvider(customUserDetailsService, passwordEncoder);
    }

    @Test
    @DisplayName("비밀번호가 같을 시 토큰을 반환한다..")
    void match_password_test() {
        MemberEntity mockEntity = new MemberEntity(1L, "mangjoo", passwordEncoder.encode("1234"), Role.USER);
        given(customUserDetailsService.loadUserByUsername("mangjoo")).willReturn(mockEntity);

        Authentication token = loginProvider.authenticate(new UsernamePasswordAuthenticationToken("mangjoo", "1234"));
        String authority = token.getAuthorities().stream().findFirst().get().getAuthority();

        assertThat(token.getPrincipal()).isEqualTo(1L);
        assertThat(authority).isEqualTo("USER");
    }

    @Test
    @DisplayName("비밀번호가 다를 시 예외를 던진다.")
    void not_match_password_test() {
        MemberEntity mockEntity = new MemberEntity(1L, "mangjoo", passwordEncoder.encode("1234"), Role.USER);
        given(customUserDetailsService.loadUserByUsername("mangjoo")).willReturn(mockEntity);

        assertThatThrownBy(() -> loginProvider.authenticate(new UsernamePasswordAuthenticationToken("mangjoo", "12345")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("password not match");
    }
}