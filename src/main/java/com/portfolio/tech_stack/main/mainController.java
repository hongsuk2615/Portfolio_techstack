package com.portfolio.tech_stack.main;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class mainController {
    /**
     * 메인 페이지
     *
     * @GetMapping("/"): GET 요청이 "/" 경로로 들어오면 이 메서드 실행
     * @return "index": templates/index.html을 찾아서 렌더링
     */
    @GetMapping("/")
    public String home() {
        return "index";
    }
}
