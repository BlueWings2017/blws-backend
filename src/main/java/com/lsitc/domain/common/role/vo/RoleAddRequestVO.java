package com.lsitc.domain.common.role.vo;

import com.lsitc.domain.common.role.entity.RoleEntity;
import javax.validation.constraints.NotBlank;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class RoleAddRequestVO {

  @NotBlank(message = "권한명이 필요합니다.")
  private final String roleNm;

  private final String rmrk;

  public RoleEntity toEntity() {
    return RoleEntity.builder()
        .name(roleNm)
        .remark(rmrk)
        .build();
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}
