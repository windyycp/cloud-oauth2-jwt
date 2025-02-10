package com.xxx.authserver.oauth;

import com.xxx.authcommon.util.ErrorUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class MyExceptionFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        try {

            filterChain.doFilter(request, response);
        } catch (Exception e) {
            e.printStackTrace();

            // 系统默认异常不处理
            if (e instanceof AuthenticationException || e instanceof AccessDeniedException) {
                throw e;
            }
            // 处理其他自定义异常
            ErrorUtil.responseError(response, e, HttpServletResponse.SC_BAD_REQUEST);
        }
    }
}