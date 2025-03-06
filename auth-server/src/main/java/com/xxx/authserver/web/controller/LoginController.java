package com.xxx.authserver.web.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/")
public class LoginController {

    /**
     * 自定义登录页，覆盖默认oauth2的登录页
     *
     * @return String
     * @author yuchaopeng, 2025/3/6 下午2:22
     */
    @GetMapping("/login")
    public String login() {
        return "login";
    }


}
