package com.xxx.authcommon.util;

import com.alibaba.fastjson2.JSON;
import jakarta.servlet.http.HttpServletResponse;

import java.util.HashMap;
import java.util.Map;

public class ErrorUtil {

    public static void responseError(HttpServletResponse response, Exception e) {
        responseError(response, e, HttpServletResponse.SC_BAD_REQUEST);
    }

    public static void responseError(HttpServletResponse response, Exception e, int status) {
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(status);
        Map<String, Object> error = new HashMap<>();
        error.put("code", e.getClass().getSimpleName());
        error.put("message", e.getMessage());
        try {
            response.getWriter().write(JSON.toJSONString(error));
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

}
