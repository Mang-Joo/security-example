package com.mangjoo.io.securityexample.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/user")
public class TestController {

    @GetMapping("/test")
    public ResponseEntity<String> test(@AuthenticationPrincipal Long id) {
        System.out.println("test");
        System.out.println("principal.getName(); = " + id);
        return ResponseEntity.ok(id.toString());
    }

}
