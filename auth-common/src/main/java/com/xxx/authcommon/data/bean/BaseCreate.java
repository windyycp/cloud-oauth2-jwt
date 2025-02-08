package com.xxx.authcommon.data.bean;

import com.baomidou.mybatisplus.annotation.FieldFill;
import com.baomidou.mybatisplus.annotation.TableField;
import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * 基础实体，创建人和创建时间
 *
 * @author yuchaopeng
 * @date 2023/4/21 2:23 PM
 **/
@Data
public class BaseCreate extends Base {

    /*** 创建人 */
    @TableField(fill = FieldFill.INSERT)
    private Long createBy;

    /*** 创建时间 */
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    @TableField(fill = FieldFill.INSERT)
    private LocalDateTime createAt;

}
