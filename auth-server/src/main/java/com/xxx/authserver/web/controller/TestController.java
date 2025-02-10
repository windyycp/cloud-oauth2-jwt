package com.xxx.authserver.web.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.util.Base64;
import java.util.Map;

@RestController
@RequestMapping("/test")
public class TestController {

    @Autowired
    private RestTemplate restTemplate;

    @RequestMapping("/hello")
    public String hello() {
        return "hello";
    }

    /**
     * 通过授权码获取token
     *
     * @author yuchaopeng, 2025/2/8 下午3:28
     */
    @RequestMapping("/code")
    public String token(@RequestParam String code) throws Exception {

        String clientId = "my-client";
        String clientSecret = "my-secret";

        // 添加参数
        MultiValueMap<String, String> param = new LinkedMultiValueMap<>();
        param.add("grant_type", AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
        param.add("redirect_uri", "http://127.0.0.1:8080/test/code");
        param.add("client_id", clientId);
        param.add("client_secret", clientSecret);
        param.add("code", code);
        param.add("sms_code", "666666"); // 二次认证使用， 非必须

        // 设置请求头
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setBasicAuth(Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes("utf-8")));

        // 创建HttpEntity对象
        HttpEntity requestEntity = new HttpEntity<>(param, headers);

        // 发送POST请求
        Map<String, Object> response = restTemplate.postForObject("http://127.0.0.1:8080/oauth2/token", requestEntity, Map.class);

        return response.get("access_token").toString();

    }

}
