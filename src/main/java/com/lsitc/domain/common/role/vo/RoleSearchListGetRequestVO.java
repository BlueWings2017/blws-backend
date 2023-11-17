package com.lsitc.domain.common.role.vo;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.lsitc.domain.common.role.entity.RoleEntity;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class RoleSearchListGetRequestVO {

  private final Long roleId;
  private final String roleNm;
  
  public RoleEntity toEntity() {
    return RoleEntity.builder()
        .id(roleId)
        .name(roleNm)
        .build();
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}
