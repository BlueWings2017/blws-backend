package com.lsitc.domain.common.menu.dao;

import java.util.List;
import org.apache.ibatis.annotations.Mapper;
import com.lsitc.domain.common.menu.entity.MenuEntity;

@Mapper
public interface MenuDAO {

  MenuEntity selectMenuById(MenuEntity menuEntity);

  List<MenuEntity> selectAll();

  List<MenuEntity> selectMenuByConditions(MenuEntity menuEntity);
  
  int insertMenuList(List<MenuEntity> menuEntityList);

  int updateMenuById(List<MenuEntity> menuEntity);

  int updateMenuByParentsId(List<MenuEntity> menuEntity);

  int insertMenuWithId(List<MenuEntity> menuEntity);

  int deleteMenuById(List<MenuEntity> menuEntity);

}