package com.xxx.authserver.oauth;

import com.xxx.authcommon.util.ErrorUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

public class MyErrorResponseHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) {
        ErrorUtil.responseError(response, exception, HttpServletResponse.SC_UNAUTHORIZED);
    }
}
