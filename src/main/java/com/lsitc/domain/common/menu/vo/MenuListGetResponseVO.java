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
public class MenuListGetResponseVO {

  private final List<MenuListVO> menuList;
  private final List<MenuTreeVO> treeList;

  @Builder
  private MenuListGetResponseVO(List<MenuListVO> menuList, List<MenuTreeVO> treeList) {
    this.menuList = menuList;
    this.treeList = treeList;
  }

  public static MenuListGetResponseVO of(List<MenuEntity> menuEntityList) {
    List<MenuListVO> menuList =
        menuEntityList.stream().map(MenuListVO::of).collect(Collectors.toList());
    
    List<MenuTreeVO> treeList =
        menuEntityList.stream().map(MenuTreeVO::of).collect(Collectors.toList());
    
    treeList = TreeUtils.getTree(treeList);
    
    return builder()
        .menuList(menuList)
        .treeList(treeList)
        .build();
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}
