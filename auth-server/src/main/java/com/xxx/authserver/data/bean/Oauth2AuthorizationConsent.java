package com.xxx.authserver.data.bean;

import lombok.Data;

@Data
public class Oauth2AuthorizationConsent {
    private String registeredClientId;
    private String principalName;
    private String authorities;
}