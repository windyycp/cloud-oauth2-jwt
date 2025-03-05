package com.xxx.authcommon.util;

import com.alibaba.fastjson2.JSON;
import jakarta.servlet.http.HttpServletRequest;

/**
 * 请求工具类
 *
 * @author yuchaopeng, 2023/5/9 11:42 AM
 **/
public class RequestUtil {


    /**
     * 获取请求头
     *
     * @param request
     * @param headerName
     * @return String
     * @author yuchaopeng, 2024/5/31 8:41
     */
    public static String getHeader(HttpServletRequest request, String... headerName) {
        for (String name : headerName) {
            if (request.getHeader(name) != null) {
                return request.getHeader(name);
            }
        }
        return null;
    }

    /**
     * 获取请求访问域，如http://auth.bortron.com
     *
     * @param request
     * @param headerName
     * @return java.lang.String
     * @author yuchaopeng, 2023/5/22 9:06 AM
     */
    public static String getOrigin(HttpServletRequest request, String... headerName) {
        String origin = getHeader(request, headerName);
        if (origin != null) {
            int pos = origin.indexOf('/', 8);
            origin = origin.substring(0, pos > -1 ? pos : origin.length());
        }
        return origin;
    }

    /**
     * 从参数列表，读取body的json字符串
     *
     * @param args
     * @return java.lang.String
     * @author yuchaopeng, 2023/12/15 13:50
     */
    public static String getJsonStrBody(Object[] args) {
        String body = "{}";
        if (args != null && args.length > 0) {
            if (args[0] instanceof String) {
                body = (String) args[0];
            } else {
                body = JSON.toJSONString(args[0]);
            }
            body = body.replaceAll("\r\n", "");
        }
        return body;
    }

}
