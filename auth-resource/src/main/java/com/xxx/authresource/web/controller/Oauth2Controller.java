package com.xxx.authresource.web.controller;

import com.xxx.authcommon.common.CommonR;
import com.xxx.authcommon.component.RedisService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.view.RedirectView;

import java.util.Base64;
import java.util.Map;
import java.util.UUID;

@Controller
@RequestMapping("/oauth2")
public class Oauth2Controller {

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private RedisService redisService;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String oauth2ServerUri;

    @GetMapping("/login")
    public RedirectView login(@RequestParam String client_id,
                              @RequestParam String redirect_uri,
                              @RequestParam String state) {

        String uid = UUID.randomUUID().toString().replaceAll("-", "");
        String serverUri = "http://127.0.0.1:8081/oauth2/code/" + uid;
        redisService.set("oauth2:uid:client_uri" + uid, redirect_uri, 300);
        redisService.set("oauth2:uid:server_uri" + uid, serverUri, 300);
        redisService.set("oauth2:uid:state" + uid, state, 300);

        // 重定向oauth2登录页面
        String loginUrl = String.format("%s/oauth2/authorize?response_type=%s&scope=%s&client_id=%s&redirect_uri=%s",
                oauth2ServerUri,
                "code",
                "openid",
                client_id,
                serverUri);

        return new RedirectView(loginUrl);
    }

    @GetMapping("/code/{uid}")
    public RedirectView token(@PathVariable String uid, @RequestParam String code) throws Exception {

        String clientId = "my-client";
        String clientSecret = "my-secret";

        String serverUri = redisService.get("oauth2:uid:server_uri" + uid);
        Assert.notNull(serverUri, "serverUri is null");

        String clientUri = redisService.get("oauth2:uid:client_uri" + uid);
        Assert.notNull(clientUri, "clientUri is null");

        // csrf校验码
        String state = redisService.get("oauth2:uid:state" + uid);

        // 添加参数
        MultiValueMap<String, String> param = new LinkedMultiValueMap<>();
        param.add("grant_type", AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
        param.add("redirect_uri", serverUri);
        param.add("client_id", clientId);
        param.add("client_secret", clientSecret);
        param.add("code", code);
        param.add("sms_code", "666666"); // 二次认证使用， 非必须

        // 设置请求头
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setBasicAuth(Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes("utf-8")));

        // 创建HttpEntity对象
        HttpEntity request = new HttpEntity<>(param, headers);

        // 发送POST请求
        Map<String, Object> response = restTemplate.postForObject(oauth2ServerUri + "/oauth2/token", request, Map.class);

        // 读取token信息
        String accessToken = response.get("access_token").toString();

        return new RedirectView(String.format("%s?access_token=%s&state=%s", clientUri, accessToken, state));

    }

    @GetMapping("/logout")
    @ResponseBody
    public CommonR logout(HttpServletRequest request, HttpServletResponse response) {
        new SecurityContextLogoutHandler().logout(request, response, null);
        String token = request.getHeader("authorization").replaceAll("Bearer", "").trim();
        String referer = request.getHeader("referer");
        return CommonR.OK(String.format("%s/signOut?redirectUri=%s&accessToken=%s", oauth2ServerUri, referer, token));
    }

}
