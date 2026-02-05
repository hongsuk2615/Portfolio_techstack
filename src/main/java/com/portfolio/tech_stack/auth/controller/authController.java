package com.portfolio.tech_stack.auth.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class authController {

    @GetMapping("/auth")
    public String index(){
        return "redirect:/user/info";
    }


    @GetMapping("/auth/login")
    public String login(){
        // 이미 로그인된 경우 사용자 정보 페이지로 리다이렉트
        if (isAuthenticated()) {
            return "redirect:/user/info";
        }
        return "auth/login";
    }

    @GetMapping("/auth/register")
    public String register(){
        // 이미 로그인된 경우 사용자 정보 페이지로 리다이렉트
        if (isAuthenticated()) {
            return "redirect:/user/info";
        }
        return "auth/register";
    }

    /**
     * 사용자 로그인 여부 체크
     */
    private boolean isAuthenticated() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null
                && authentication.isAuthenticated()
                && !(authentication.getPrincipal() instanceof String); // "anonymousUser"가 아닌지 확인
    }
}
