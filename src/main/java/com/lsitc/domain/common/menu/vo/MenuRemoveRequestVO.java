package com.lsitc.domain.common.menu.vo;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.lsitc.domain.common.menu.entity.MenuEntity;
import lombok.Getter;

@Getter
public class MenuRemoveRequestVO {

  private final String menuId;

  @JsonCreator
  public MenuRemoveRequestVO(String menuId) {
    this.menuId = menuId;
  }

  public MenuEntity toEntity() {
    return MenuEntity.builder()
        .id(Long.valueOf(menuId))
        .build();
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}
