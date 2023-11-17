package com.lsitc.domain.common.menu.vo;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.lsitc.domain.common.menu.entity.MenuEntity;
import com.lsitc.domain.model.BooleanState;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class MenuModifyRequestVO {

  private final String menuId;
  private final String menuNm;
  private final String menuEngNm;
  private final String upMenuId;
  private final String url;
  private final String useFg;
  private final String sortSeq;
  private final int roleId;
  private final String iconClass;

  public MenuEntity toEntity() {
    return MenuEntity.builder()
        .id(menuId != null ? Long.valueOf(menuId) : null)
        .name(menuNm)
        .englishName(menuEngNm)
        .parentsId(upMenuId != null ? Long.valueOf(upMenuId) : null)
        .url(url)
        .isUsed(convertUseFg())
        .sortSequence(Integer.valueOf(sortSeq))
        .roleId(roleId)
        .iconClass(iconClass)
        .build();
  }

  private Boolean convertUseFg() {
    return BooleanState.of(String.valueOf(this.useFg)).getBooleanValue();
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}