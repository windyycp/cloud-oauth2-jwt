package com.xxx.authresource.data.vo;

import com.xxx.authresource.data.bean.SysUser;
import lombok.Data;

import java.util.List;

@Data
public class SysUserVO extends SysUser {

    private List<String> roles;

}
