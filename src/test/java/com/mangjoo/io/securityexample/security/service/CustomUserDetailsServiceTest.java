package com.mangjoo.io.securityexample.security.service;

import com.mangjoo.io.securityexample.application.persistence.MemberEntity;
import com.mangjoo.io.securityexample.application.persistence.MemberJpaRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
class CustomUserDetailsServiceTest {

    @InjectMocks
    private CustomUserDetailsService customUserDetailsService;

    @Mock
    private MemberJpaRepository memberJpaRepository;


    @Test
    @DisplayName("유저를 찾을 수 없을 때 예외를 던진다.")
    void not_found_user() {
        given(memberJpaRepository.findByUsername("mangjoo")).willReturn(Optional.empty());

        assertThatThrownBy(() -> customUserDetailsService.loadUserByUsername("mangjoo"))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessage("user not found");
    }

    @Test
    @DisplayName("유저를 찾을 수 있을 때 유저를 반환한다.")
    void found_user() {
        given(memberJpaRepository.findByUsername("mangjoo")).willReturn(Optional.of(new MemberEntity(
                1L, "mangjoo", "1234", null
        )));

        MemberEntity entity = customUserDetailsService.loadUserByUsername("mangjoo");

        assertThat(entity).isNotNull();
    }
}