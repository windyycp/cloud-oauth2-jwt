package com.xxx.authserver.oauth;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;

public class MyAuthenticationFailureHandler implements AuthenticationFailureHandler {
    
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        // 获取异常信息
        String message = exception.getMessage();
        if (message.contains("UserDetailsService returned null")) {
            message = "用户不存在";
        }
        // 记录异常信息
        request.getSession().setAttribute("error", message);
        // 重定向到登录页面
        response.sendRedirect("/login");
    }

}
