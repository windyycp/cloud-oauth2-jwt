package com.xxx.authcommon.data.bean;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import lombok.Data;

import java.io.Serializable;

/**
 * 基础实体，ID主键
 *
 * @author yuchaopeng
 * @date 2023/4/21 2:23 PM
 **/
@Data
public class Base implements Serializable {

    /*** 主键ID */
    @TableId(value = "Id", type = IdType.AUTO)
    private Long id;

}
