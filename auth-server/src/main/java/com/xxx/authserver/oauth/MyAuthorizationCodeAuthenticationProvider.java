package com.xxx.authserver.oauth;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;

/**
 * 扩展OAuth2AuthorizationCodeAuthenticationProvider认证，支持二次认证（如短信验证码、邮箱验证码）
 *
 * @author yuchaopeng, 2025/2/10 上午9:49
 */
public class MyAuthorizationCodeAuthenticationProvider implements AuthenticationProvider {

    private OAuth2AuthorizationCodeAuthenticationProvider delegate;

    public MyAuthorizationCodeAuthenticationProvider(OAuth2AuthorizationService authorizationService,
                                                     OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
        this.delegate = new OAuth2AuthorizationCodeAuthenticationProvider(authorizationService, tokenGenerator);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        // 强制转换为 OAuth2AuthorizationCodeAuthenticationToken
        OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication =
                (OAuth2AuthorizationCodeAuthenticationToken) authentication;

        // 获取短信验证码（假设短信验证码通过请求参数传递）
        Object smsCode = authorizationCodeAuthentication.getAdditionalParameters().get("sms_code");

        // 验证短信验证码
        if (!"666666".equals(smsCode)) {
//            throw new RuntimeException("Invalid SMS code");
        }

        // 调用原始的 OAuth2AuthorizationCodeAuthenticationProvider 进行授权码验证和令牌生成
        return delegate.authenticate(authentication);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
