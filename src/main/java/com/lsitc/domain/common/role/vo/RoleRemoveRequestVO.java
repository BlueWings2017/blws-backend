package com.lsitc.domain.common.role.vo;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.PositiveOrZero;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.lsitc.domain.common.role.entity.RoleEntity;
import lombok.Getter;

@Getter
public class RoleRemoveRequestVO {

  @NotNull
  @PositiveOrZero(message = "음수의 ID는 사용할 수 없습니다.")
  private final Long roleId;

  @JsonCreator
  public RoleRemoveRequestVO(Long roleId) {
    this.roleId = roleId;
  }

  public RoleEntity toEntity() {
    return RoleEntity.builder()
        .id(roleId)
        .build();
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}
