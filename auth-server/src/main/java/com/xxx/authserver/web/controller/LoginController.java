package com.xxx.authserver.web.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

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
    public ModelAndView login(HttpServletRequest request) {
        ModelAndView model = new ModelAndView("login");
        model.addObject("error", request.getSession().getAttribute("error"));
        return model;
    }

    /**
     * 自定义退出登录，并重定向来源地址
     *
     * @param request
     * @param response
     * @param redirectUri
     * @return RedirectView
     * @author yuchaopeng, 2025/3/6 下午6:14
     */
    @GetMapping("/logout")
    public RedirectView logout(HttpServletRequest request, HttpServletResponse response,
                               @RequestParam(required = false) String redirectUri,
                               @RequestParam(required = false) String accessToken) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }
        return new RedirectView(redirectUri);
    }

}
