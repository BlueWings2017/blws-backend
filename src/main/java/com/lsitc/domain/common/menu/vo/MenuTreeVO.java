package com.lsitc.domain.common.menu.vo;

import java.time.LocalDateTime;
import com.lsitc.domain.common.menu.entity.MenuEntity;
import com.lsitc.domain.model.BooleanState;
import com.lsitc.global.common.TreeAbstractVO;
import lombok.Builder;
import lombok.Getter;

@Getter
public class MenuTreeVO extends TreeAbstractVO {
  
  private final Long menuId;
  private final String menuNm;
  private final String menuEngNm;
  private final Long upMenuId;
  private final String url;
  private final String useFg;
  private final int sortSeq;
  private final String text;
  private final boolean expanded;
  private final boolean selected;
  private final String path;
  private final String regUserNo;
  private final LocalDateTime regDttm;
  private final String procUserNo;
  private final LocalDateTime procDttm;
  private final int roleId;
  private final String iconClass;

  @Builder
  private MenuTreeVO(Long menuId, String menuNm, String menuEngNm, Long upMenuId, String url,
      String useFg, int sortSeq, String text, boolean expanded, boolean selected, String path,
      String regUserNo, LocalDateTime regDttm, String procUserNo, LocalDateTime procDttm, int roleId, String iconClass) {
    this.menuId = menuId;
    this.menuNm = menuNm;
    this.menuEngNm = menuEngNm;
    this.upMenuId = upMenuId;
    this.url = url;
    this.useFg = useFg;
    this.sortSeq = sortSeq;
    this.text = text;
    this.expanded = expanded;
    this.selected = selected;
    this.path = path;
    this.regUserNo = regUserNo;
    this.regDttm = regDttm;
    this.procUserNo = procUserNo;
    this.procDttm = procDttm;
    this.roleId = roleId;
    this.iconClass = iconClass;
  }

  public static MenuTreeVO of(MenuEntity menuEntity) {
    return of(menuEntity, null, false);
  }
  
  public static MenuTreeVO of(MenuEntity menuEntity, String locale, boolean isHorizontal) {
    return builder()
        .menuId(menuEntity.getId())
        .menuNm(getNameByLocale(menuEntity, locale))
        .menuEngNm(menuEntity.getEnglishName())
        .upMenuId(menuEntity.getParentsId())
        .url(isHorizontal ? null : menuEntity.getUrl())
        .useFg(convertBoolean(menuEntity.getIsUsed()))
        .sortSeq(menuEntity.getSortSequence())
        .text(getNameByLocale(menuEntity, locale))
        .expanded(false)
        .selected(false)
        .path(isHorizontal ? menuEntity.getUrl() : null)
        .regUserNo(menuEntity.getCreatedBy())
        .regDttm(menuEntity.getCreatedDate())
        .procUserNo(menuEntity.getLastModifiedBy())
        .procDttm(menuEntity.getLastModifiedDate())
        .roleId(menuEntity.getRoleId())
        .iconClass(menuEntity.getIconClass())
        .build();
  }

  private static String convertBoolean(int booleanValue) {
    return booleanValue > 0 ? "1": "0";
  }
  
  private static String getNameByLocale(MenuEntity menuEntity, String locale) {
    return "ko-KR".equals(locale) ? menuEntity.getName()
        : "en-US".equals(locale) ? menuEntity.getEnglishName() : menuEntity.getName();
  }

  @Override
  public Long id() {
    return this.menuId;
  }

  @Override
  public Long parentsId() {
    return this.upMenuId;
  }
}