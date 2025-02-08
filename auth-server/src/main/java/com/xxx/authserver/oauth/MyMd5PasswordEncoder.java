package com.xxx.authserver.oauth;

import com.xxx.authcommon.util.MD5Utils;
import org.springframework.security.crypto.password.PasswordEncoder;

public class MyMd5PasswordEncoder implements PasswordEncoder {

    @Override
    public String encode(CharSequence rawPassword) {
        return MD5Utils.md5(rawPassword.toString());
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return MD5Utils.md5(rawPassword.toString()).equals(encodedPassword);
    }

}
