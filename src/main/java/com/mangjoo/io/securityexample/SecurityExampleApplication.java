package com.mangjoo.io.securityexample;

import com.mangjoo.io.securityexample.application.persistence.MemberEntity;
import com.mangjoo.io.securityexample.application.persistence.MemberJpaRepository;
import com.mangjoo.io.securityexample.application.persistence.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class SecurityExampleApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityExampleApplication.class, args);
    }

    @Bean
    CommandLineRunner commandLineRunner(PasswordEncoder passwordEncoder, MemberJpaRepository memberRepository) {
        return args -> {
            MemberEntity memberEntity = MemberEntity.builder()
                    .username("user")
                    .password(passwordEncoder.encode("1234"))
                    .role(Role.USER)
                    .build();
            memberRepository.save(memberEntity);
        };
    }

}
