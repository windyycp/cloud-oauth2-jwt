package com.xxx.authserver.oauth;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.function.Consumer;

/**
 * 自定义授权请求中的RedirectUri验证
 *
 * @author yuchaopeng, 2025/2/26 下午5:59
 */
public class MyRedirectUriValidator implements Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> {

    @Override
    public void accept(OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext) {
        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
                authenticationContext.getAuthentication();
        RegisteredClient registeredClient = authenticationContext.getRegisteredClient();
        String requestedRedirectUri = authorizationCodeRequestAuthentication.getRedirectUri();

        // RedirectUri必填
        if (StringUtils.isBlank(requestedRedirectUri)) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REDIRECT_URI);
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
        }

        // RedirectUri与数据库中的匹配
        boolean matchRedirectUri = false;
        for (String registeredRedirectUri : registeredClient.getRedirectUris()) {
            UriComponentsBuilder registeredRedirect = UriComponentsBuilder.fromUriString(registeredRedirectUri);
            if (requestedRedirectUri.contains(registeredRedirect.toUriString())) {
                matchRedirectUri = true;
            }
        }

        // RedirectUri匹配失败
        if (!matchRedirectUri) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REDIRECT_URI);
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
        }
    }

}