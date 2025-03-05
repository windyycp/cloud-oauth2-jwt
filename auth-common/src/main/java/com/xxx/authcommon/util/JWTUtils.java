package com.xxx.authcommon.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * JWT 工具类
 *
 * @author Pumpkin
 * @createTime 2023/2/15 20:50
 */
@Slf4j
public class JWTUtils {

    private static final String secret = "www.kotron.com&eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    private static final String issuer = "www.kotron.com";
    private static final String audience = "Client";
    private static final int timeout = 60 * 24; //  单位分钟;


    /**
     * 生成 token
     *
     * @param payload token携带的信息
     * @return token加密字符串
     */
    public static String getToken(Map<String, Object> payload) {
        return getToken(payload, timeout);
    }

    /**
     * 生成 token
     *
     * @param payload       token携带的信息
     * @param expiredSecond 过期时间（单位秒）
     * @return token加密字符串
     */
    public static String getToken(Map<String, Object> payload, int expiredSecond) {

        // 设置过期时间
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.SECOND, expiredSecond);
        JWTCreator.Builder builder = JWT.create();
        builder.withIssuer(issuer);
        builder.withAudience(audience);
        // 构建 payload
        payload.forEach((k, v) -> {
            if (v instanceof Long l) {
                builder.withClaim(k, l);
            }
            if (v instanceof String s) {
                builder.withClaim(k, s);
            }
            if (v instanceof Integer i) {
                builder.withClaim(k, i);
            }
            if (v instanceof Double d) {
                builder.withClaim(k, d);
            }
            if (v instanceof Boolean b) {
                builder.withClaim(k, b);
            }
            if (v instanceof Date d) {
                builder.withClaim(k, d);
            }
            if (v instanceof List l) {
                builder.withClaim(k, l);
            }
            if (v instanceof Map m) {
                builder.withClaim(k, m);
            }
        });
        // 指定过期时间和签名算法
        return builder.withExpiresAt(calendar.getTime()).sign(Algorithm.HMAC256(secret));
    }

    /**
     * 解析 token
     *
     * @param token token 字符串
     * @return 解析后的 token
     */
    public static DecodedJWT verify(String token) {
        try {
            DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC256(secret)).build().verify(token);
            Date expiresAt = decodedJWT.getExpiresAt();
            if (expiresAt.before(new Date())) {
                return null;
            }
            String userName = decodedJWT.getClaim("Account").asString();
            if (StringUtils.isEmpty(userName)) {
                return null;
            }
            return decodedJWT;
        } catch (Exception e) {
            log.error("jwt verify error: {}", e);
        }
        return null;
    }

    public static DecodedJWT verifyRSA256(String token, RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        try {
            DecodedJWT decodedJWT = JWT.require(Algorithm.RSA256(publicKey, null)).build().verify(token);
            Date expiresAt = decodedJWT.getExpiresAt();
            if (expiresAt.before(new Date())) {
                return null;
            }
            String sub = decodedJWT.getClaim("sub").asString();
            if (StringUtils.isEmpty(sub)) {
                return null;
            }
            return decodedJWT;
        } catch (Exception e) {
            log.error("jwt verify error: {}", e);
        }
        return null;
    }

    public static String getValueRSA256(String token, RSAPublicKey publicKey, String claimName) {
        DecodedJWT decodedJWT = verifyRSA256(token, publicKey, null);
        if (decodedJWT == null) {
            return null;
        }
        return decodedJWT.getClaims().get(claimName).asString();
    }

    public static void main(String[] args) {
        test1();
        test2();
    }

    private static void test1() {
        Map<String, Object> payload = Map.of("Id", 1001, "Account", "admin");
        String token = getToken(payload);
        System.out.println(token);
        DecodedJWT decodedJWT = verify(token);
        System.out.println(decodedJWT.getClaims());
    }

    private static void test2() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJJZCI6IjEiLCJOYW1lIjoiYWRtaW4iLCJBY2NvdW50IjoiYWRtaW4iLCJFbWFpbCI6ImFkbWluQHFxLmNvbSIsIk1vYmlsZSI6IjEyMzQ1Njc4OSIsIkNvbXBhbnkiOiIiLCJEZXBhcnRtZW50IjoiIiwiVXNlclR5cGUiOiJBZG1pbiIsIlN0YXRpb25JZHMiOiIiLCJGb2N1c1N0YXRpb25JZHMiOiIiLCJDdWJlSWRzIjoiIiwiRW11SWRzIjoiIiwic3ViIjoiYWRtaW4iLCJqdGkiOiJiYzcyZGE4NS1lZWFjLTQ1OGQtYTc0Zi1lZjFiMjgxYzU5MTAiLCJpYXQiOjE3MTM0ODg1ODksIm5iZiI6MTcxMzQ4ODU4OSwiZXhwIjoxNzEzNTc0OTg5LCJpc3MiOiJ3d3cua290cm9uLmNvbSIsImF1ZCI6IkNsaWVudCJ9.ndjjoANTTrmglJHYQwG9d1oYzdn-jLPtIcTWXKFEsPs";

        DecodedJWT decodedJWT = verify(token);
        //获取JWT中的数据,注意数据类型一定要与添加进去的数据类型一致,否则取不到数据
        System.out.println(decodedJWT.getClaim("Id").asLong());
        System.out.println(decodedJWT.getClaim("Account").asString());
        System.out.println(decodedJWT.getClaim("Email").asString());
        System.out.println(decodedJWT.getExpiresAt());
        System.out.println(decodedJWT.getClaims());

    }


}