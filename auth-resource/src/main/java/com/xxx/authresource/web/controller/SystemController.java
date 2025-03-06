package com.xxx.authresource.web.controller;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.xxx.authcommon.common.CommonR;
import com.xxx.authcommon.util.JWTUtils;
import com.xxx.authcommon.util.RSAUtil;
import com.xxx.authresource.data.bean.SysUser;
import com.xxx.authresource.data.vo.SysUserVO;
import com.xxx.authresource.web.mapper.SysUserMapper;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/system")
public class SystemController {

    @Autowired
    private SysUserMapper sysUserMapper;

    @RequestMapping("/user/user_info")
    public CommonR userInfo(@RequestHeader("authorization") String authorization) throws Exception {
        String token = authorization.replace("Bearer", "").trim();
        String userName = JWTUtils.getValueRSA256(token, (RSAPublicKey) RSAUtil.loadPublicKey(), "sub");
        SysUser user = sysUserMapper.selectOne(new LambdaQueryWrapper<SysUser>().eq(SysUser::getUserName, userName));
        SysUserVO vo = new SysUserVO();
        BeanUtils.copyProperties(user, vo);
        vo.setRoles(List.of("default"));
        return CommonR.OK(vo);
    }

    @RequestMapping("/menu/list")
    public CommonR menuList() {
        Map<String, Object> meta = Map.of("isKeepAlive", true,
                "isHide", false,
                "title", "message.router.home",
                "roles", List.of("default"));

        Map<String, Object> menu = Map.of("name", "首页",
                "menuType", "menu",
                "component", "home/index",
                "path", "/home",
                "isHide", false,
                "isKeepAlive", true,
                "meta", meta);

        return CommonR.OK(List.of(menu));
    }

}
