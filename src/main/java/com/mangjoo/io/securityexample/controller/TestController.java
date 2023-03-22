package com.mangjoo.io.securityexample.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class TestController {

    @GetMapping("/test")
    public void test(@AuthenticationPrincipal Principal principal) {
        System.out.println("test");
        System.out.println("principal.getName(); = " + principal.getName());

    }

}
