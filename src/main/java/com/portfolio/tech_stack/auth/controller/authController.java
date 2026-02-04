package com.portfolio.tech_stack.auth.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class authController {

    @GetMapping("/auth")
    public String index(){
        return "auth/index";
    }


    @GetMapping("/auth/login")
    public String login(){
        return "auth/login";
    }
}
