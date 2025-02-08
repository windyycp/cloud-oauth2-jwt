package com.xxx.authresource.web.controller;

import com.alibaba.fastjson2.JSON;
import com.xxx.authresource.data.bean.SysUser;
import com.xxx.authresource.web.mapper.SysUserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private SysUserMapper sysUserMapper;

    @RequestMapping("/info")
    public String info() {
        SysUser user = sysUserMapper.selectById(1L);
        return JSON.toJSONString(user);
    }


}
