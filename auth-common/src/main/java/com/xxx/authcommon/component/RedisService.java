package com.xxx.authcommon.component;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * 基础Redis服务
 **/
@Component
public class RedisService {

    @Autowired
    private StringRedisTemplate redisTemplate;

    /**
     * 添加数据
     *
     * @param key
     * @param value
     * @return void
     */
    public void set(String key, String value) {
        redisTemplate.opsForValue().set(key, value);
    }

    /**
     * 添加超时数据
     *
     * @param key
     * @param value
     * @param timeout 超时时间，单位秒
     * @return void
     */
    public void set(String key, String value, long timeout) {
        redisTemplate.opsForValue().set(key, value, timeout, TimeUnit.SECONDS);
    }

    /**
     * 读取数据
     *
     * @param key
     * @return java.lang.String
     */
    public String get(String key) {
        return redisTemplate.opsForValue().get(key);
    }

    /**
     * 设置map类型的key,value
     *
     * @param key     redis的主键
     * @param hashKey map内的key
     * @param value   map内的value
     * @return void
     */
    public void set(String key, String hashKey, Object value) {
        redisTemplate.opsForHash().put(key, hashKey, value);
    }

    /**
     * 读取map类型的key,value
     *
     * @param key     redis的主键
     * @param hashKey map内的key
     * @return Object
     */
    public Object get(String key, String hashKey) {
        return redisTemplate.opsForHash().get(key, hashKey);
    }

    /**
     * 同步删除多个key
     *
     * @param keys key的集合
     * @return java.lang.Long
     */
    public Long delete(List keys) {
        return redisTemplate.delete(keys);
    }

    /**
     * 同步删除单个key
     *
     * @param key
     * @return java.lang.Boolean
     */
    public Boolean delete(String key) {
        return redisTemplate.delete(key);
    }

}
