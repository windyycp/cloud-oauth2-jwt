package com.xxx.authcommon.common;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * 基础分页数据
 *
 * @author: yuchaopeng, 2023/4/14 2:48 PM
 **/
@Data
@AllArgsConstructor
@NoArgsConstructor
public class CommonPage implements Serializable {
    private Long page;
    private Long pageSize;
    private Long total;
}
