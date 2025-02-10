package com.xxx.authserver.oauth;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.xxx.authserver.data.bean.Oauth2AuthorizationConsent;
import com.xxx.authserver.web.mapper.Oauth2AuthorizationConsentMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Component
public class MyOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

    @Autowired
    private Oauth2AuthorizationConsentMapper authorizationConsentRepository;

    @Autowired
    private MyOAuth2RegisteredClientRepository registeredClientRepository;


    @Override
    public void save(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
        this.authorizationConsentRepository.insertOrUpdate(toEntity(authorizationConsent));
    }

    @Override
    public void remove(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
//        this.authorizationConsentRepository.deleteByRegisteredClientIdAndPrincipalName(
//                authorizationConsent.getRegisteredClientId(), authorizationConsent.getPrincipalName());
        this.authorizationConsentRepository.delete(new LambdaQueryWrapper<Oauth2AuthorizationConsent>()
                .eq(Oauth2AuthorizationConsent::getRegisteredClientId, authorizationConsent.getRegisteredClientId())
                .eq(Oauth2AuthorizationConsent::getPrincipalName, authorizationConsent.getPrincipalName())
        );
    }

    @Override
    public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        Assert.hasText(registeredClientId, "registeredClientId cannot be empty");
        Assert.hasText(principalName, "principalName cannot be empty");
//        return this.authorizationConsentRepository.findByRegisteredClientIdAndPrincipalName(
//                registeredClientId, principalName).map(this::toObject).orElse(null);
        return Optional.ofNullable(this.authorizationConsentRepository.selectOne(new LambdaQueryWrapper<Oauth2AuthorizationConsent>()
                .eq(Oauth2AuthorizationConsent::getRegisteredClientId, registeredClientId)
                .eq(Oauth2AuthorizationConsent::getPrincipalName, principalName))
        ).map(this::toObject).orElse(null);
    }

    private OAuth2AuthorizationConsent toObject(Oauth2AuthorizationConsent authorizationConsent) {
        String registeredClientId = authorizationConsent.getRegisteredClientId();
        RegisteredClient registeredClient = this.registeredClientRepository.findById(registeredClientId);
        if (registeredClient == null) {
            throw new DataRetrievalFailureException(
                    "The RegisteredClient with id '" + registeredClientId + "' was not found in the RegisteredClientRepository.");
        }

        OAuth2AuthorizationConsent.Builder builder = OAuth2AuthorizationConsent.withId(
                registeredClientId, authorizationConsent.getPrincipalName());
        if (authorizationConsent.getAuthorities() != null) {
            for (String authority : StringUtils.commaDelimitedListToSet(authorizationConsent.getAuthorities())) {
                builder.authority(new SimpleGrantedAuthority(authority));
            }
        }

        return builder.build();
    }

    private Oauth2AuthorizationConsent toEntity(OAuth2AuthorizationConsent authorizationConsent) {
        Oauth2AuthorizationConsent entity = new Oauth2AuthorizationConsent();
        entity.setRegisteredClientId(authorizationConsent.getRegisteredClientId());
        entity.setPrincipalName(authorizationConsent.getPrincipalName());

        Set<String> authorities = new HashSet<>();
        for (GrantedAuthority authority : authorizationConsent.getAuthorities()) {
            authorities.add(authority.getAuthority());
        }
        entity.setAuthorities(StringUtils.collectionToCommaDelimitedString(authorities));

        return entity;
    }
}