package com.lsitc.domain.common.menu.vo;

import java.util.List;
import java.util.stream.Collectors;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.lsitc.domain.common.menu.entity.MenuEntity;
import com.lsitc.global.util.TreeUtils;
import lombok.Builder;
import lombok.Getter;

@Getter
public class MainMenuListGetResponseVO {

  private final List<MenuListVO> menuList;
  private final List<MenuTreeVO> treeList;
  private final List<MenuTreeVO> horizTreeList;

  @Builder
  private MainMenuListGetResponseVO(List<MenuListVO> menuList, List<MenuTreeVO> treeList,
      List<MenuTreeVO> horizTreeList) {
    this.menuList = menuList;
    this.treeList = treeList;
    this.horizTreeList = horizTreeList;
  }

  public static MainMenuListGetResponseVO of(List<MenuEntity> menuEntityList, String locale) {
    List<MenuListVO> menuList = menuEntityList.stream()
        .map(entity -> MenuListVO.of(entity, locale)).collect(Collectors.toList());

    List<MenuTreeVO> treeList =
        menuEntityList.stream().map(entity -> MenuTreeVO.of(entity, locale, false)).collect(Collectors.toList());
    
    List<MenuTreeVO> horizTreeList =
        menuEntityList.stream().map(entity -> MenuTreeVO.of(entity, locale, true)).collect(Collectors.toList());
    
    treeList = TreeUtils.getTree(treeList);
    horizTreeList = TreeUtils.getTree(horizTreeList);
    
    return builder()
        .menuList(menuList)
        .treeList(treeList)
        .horizTreeList(horizTreeList)
        .build();
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}
