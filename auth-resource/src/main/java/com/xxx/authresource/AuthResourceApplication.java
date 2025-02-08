package com.xxx.authresource;

import com.xxx.authcommon.util.BaseConst;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@MapperScan(BaseConst.MAPPER_SCAN)
@ComponentScan(BaseConst.BASE_PACKAGE)
@SpringBootApplication
public class AuthResourceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthResourceApplication.class, args);
    }

}
