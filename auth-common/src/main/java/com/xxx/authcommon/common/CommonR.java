package com.xxx.authcommon.common;

import com.alibaba.fastjson2.JSON;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.Hidden;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.Map;

/**
 * 通用响应工具类
 *
 * @author: yuchaopeng, 2023/4/14 2:03 PM
 **/
@Schema(description = "统一返回实体")
@Data
@JsonInclude(value = JsonInclude.Include.NON_NULL)
public class CommonR<T> extends CommonPage {

    public static String SUCCESS_STATUS = "1";
    public static String SUCCESS_CODE = "0000";
    public static String FAIL_CODE = "1000";
    public static String FAIL_STATUS = "-1";

    @Schema(description = "返回码 成功0000/失败1000")
    private String code;

    @Schema(description = "返回状态 成功1/失败-1")
    private String status;

    @Schema(description = "返回信息")
    private String message;

    @Schema(description = "返回体")
    private T data;

    @Hidden
    private HashMap<String, Object> part;

    private CommonR() {
    }

    private CommonR(String code, String status) {
        this(code, status, null);
    }

    private CommonR(String code, String status, String message) {
        this(code, status, message, null);
    }

    private CommonR(String code, String status, String message, T data) {
        this(code, status, message, data, null, null, null);
    }

    private CommonR(String code, String status, String message, T data, Long page, Long pageSize, Long total) {
        super(page, pageSize, total);
        this.code = code;
        this.status = status;
        this.message = message;
        this.data = data;
    }

    /**
     * 成功响应
     *
     * @return common.com.kortron.cloud.base.CommonR
     * @author yuchaopeng, 2023/4/21 4:08 PM
     */
    public static <T> CommonR OK() {
        return new CommonR(SUCCESS_CODE, SUCCESS_STATUS, null, null);
    }

    /**
     * 成功响应
     *
     * @param data 响应数据
     * @return com.kortron.cloud.base.common.R
     * @author yuchaopeng, 2023/4/14 2:20 PM
     */
    public static <T> CommonR OK(T data) {
        return new CommonR(SUCCESS_CODE, SUCCESS_STATUS, null, data);
    }

    /**
     * 分页响应
     *
     * @param p
     * @return com.kortron.cloud.base.common.R
     * @author yuchaopeng, 2023/4/14 3:04 PM
     */
//    public static <T> CommonR PAGE(PageInfo<T> p) {
//        return new CommonR(SUCCESS_CODE, SUCCESS_STATUS, null, p.getList(), Long.parseLong(p.getPageNum() + ""), Long.parseLong(p.getPageSize() + ""), p.getTotal());
//    }

    /**
     * 分页响应
     *
     * @param p
     * @return com.kortron.cloud.base.common.R
     * @author yuchaopeng, 2023/4/14 3:04 PM
     */
    public static <T> CommonR PAGE(Page<T> p) {
        return new CommonR(SUCCESS_CODE, SUCCESS_STATUS, null, p.getRecords(), p.getCurrent(), p.getSize(), p.getTotal());
    }


    /**
     * 失败响应
     *
     * @return common.com.kortron.cloud.base.CommonR
     * @author yuchaopeng, 2023/4/21 2:02 PM
     */
    public static <T> CommonR FAIL() {
        return new CommonR(FAIL_CODE, FAIL_STATUS, "");
    }


    /**
     * 失败响应
     *
     * @param message
     * @return common.com.kortron.cloud.base.CommonR
     * @author yuchaopeng, 2023/5/7 10:41 AM
     */
    public static <T> CommonR FAIL(String message) {
        return new CommonR(FAIL_CODE, FAIL_STATUS, message);
    }

    /**
     * 失败响应
     *
     * @param code    错误码
     * @param message 错误原因
     * @return com.kortron.cloud.base.common.R
     * @author yuchaopeng, 2023/4/14 2:21 PM
     */
    public static <T> CommonR FAIL(String code, String message) {
        return new CommonR(code, FAIL_STATUS, message);
    }

    /**
     * 失败响应
     *
     * @param code    错误码
     * @param status  错误状态
     * @param message 错误原因
     * @return com.kortron.cloud.base.common.R
     * @author yuchaopeng, 2023/4/14 2:21 PM
     */
    public static <T> CommonR FAIL(String code, String status, String message) {
        return new CommonR(code, status, message);
    }

    /**
     * 判断是否成功
     *
     * @return boolean
     * @author yuchaopeng, 2023/4/14 3:09 PM
     */
    public boolean isSuccess() {
        return SUCCESS_CODE.equals(this.getCode());
    }

    /**
     * 设置附加数据
     *
     * @param key
     * @param value
     * @return com.kortron.cloud.base.common.R
     * @author yuchaopeng, 2023/4/14 3:10 PM
     */
    public CommonR add(String key, Object value) {
        if (this.getPart() == null) {
            this.setPart(new HashMap<>());
        }
        this.getPart().put(key, value);
        return this;
    }

    /**
     * 将当前对象转换为MAP
     *
     * @return java.util.Map<java.lang.String, java.lang.Object>
     * @author yuchaopeng, 2023/4/14 4:30 PM
     */
    public Map<String, Object> result() {
        Map<String, Object> result = new HashMap<>();
        // 当前类
        Class<?> clazz = this.getClass();
        //向上循环 遍历父类
        for (; clazz != Object.class; clazz = clazz.getSuperclass()) {
            Field[] field = clazz.getDeclaredFields();
            for (Field f : field) {
                f.setAccessible(true);
                try {
                    String name = f.getName();
                    Object value = f.get(this);
                    if (value != null && !Modifier.isStatic(f.getModifiers()) && !"part".equals(name)) {
                        result.put(f.getName(), value);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        if (part != null) {
            result.putAll(part);
        }
        return result;
    }

    public Map<String, Object> part() {
        Map<String, Object> result = new HashMap<>();
        if (part != null) {
            result.putAll(part);
        }
        return result;
    }

    public Map<String, Object> partNotNull() {
        Map<String, Object> result = new HashMap<>();
        if (part != null) {
            part.forEach((k, v) -> {
                if (v != null) {
                    result.put(k, v);
                }
            });
        }
        return result;
    }

    public static void main(String[] args) {
        System.out.println(JSON.toJSONString(CommonR.FAIL("11", "111").add("22", "22").result()));
    }


}
