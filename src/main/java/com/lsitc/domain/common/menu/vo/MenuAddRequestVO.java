package com.lsitc.domain.common.menu.vo;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.lsitc.domain.common.menu.entity.MenuEntity;
import com.lsitc.domain.model.BooleanState;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class MenuAddRequestVO {

  private final String menuNm;
  private final String menuEngNm;
  private final String upMenuId;
  private final String url;
  private final String useFg;
  private final String sortSeq;

  public MenuEntity toEntity() {
    return MenuEntity.builder()
        .name(menuNm)
        .englishName(menuEngNm)
        .parentsId(upMenuId != null ? Long.valueOf(upMenuId) : null)
        .url(url)
        .isUsed(convertUseFg())
        .sortSequence(Integer.valueOf(sortSeq))
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