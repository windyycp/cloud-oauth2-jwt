package com.xxx.authresource.data.bean;

import com.xxx.authcommon.data.bean.BaseUpdateCreate;
import lombok.Data;

/**
 * 用户信息对象 sys_user
 *
 * @author frf
 * @date 2023-05-08
 */
@Data
public class SysUser extends BaseUpdateCreate {

    /**
     * 用户账号
     */
    private String userName;

    /**
     * 用户昵称
     */
    private String nickName;

    /**
     * 用户类型（00系统用户）
     */
    private String userType;

    /**
     * 用户邮箱
     */
    private String email;

    /**
     * 手机号码
     */
    private String phone;

    /**
     * 用户性别（0男 1女 2未知）
     */
    private Integer sex;

    /**
     * 头像地址
     */
    private String avatar;

    /**
     * 密码
     */
    private String password;

    /**
     * 帐号状态（0正常 1停用）
     */
    private Boolean status;


}
