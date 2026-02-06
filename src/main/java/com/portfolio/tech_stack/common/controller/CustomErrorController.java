package com.portfolio.tech_stack.common.controller;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.webmvc.error.ErrorController;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class CustomErrorController implements ErrorController {

    @RequestMapping("/error")
    public String handleError(HttpServletRequest request, Model model) {
        Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);


        if (status != null) {
            int statusCode = Integer.parseInt(status.toString());
            String message = request.getAttribute(RequestDispatcher.ERROR_MESSAGE).toString();
            model.addAttribute("status", statusCode);
            model.addAttribute("message", message);

            // 403 Forbidden - 로그인 페이지로 리다이렉트
            if (statusCode == 403) {
                return "redirect:/auth/login";
            }
        }



        // 기타 에러 - 에러 페이지 표시
        return "error/error";
    }
}
