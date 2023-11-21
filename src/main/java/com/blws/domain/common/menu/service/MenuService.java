package com.blws.domain.common.menu.service;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.blws.domain.common.menu.dao.MenuDAO;
import com.blws.domain.common.menu.entity.MenuEntity;
import com.blws.domain.common.menu.exception.MenuException;
import com.blws.domain.common.menu.vo.MainMenuListGetRequestVO;
import com.blws.domain.common.menu.vo.MainMenuListGetResponseVO;
import com.blws.domain.common.menu.vo.MenuAddRequestVO;
import com.blws.domain.common.menu.vo.MenuAddResponseVO;
import com.blws.domain.common.menu.vo.MenuListGetResponseVO;
import com.blws.domain.common.menu.vo.MenuModifyRequestVO;
import com.blws.domain.common.menu.vo.MenuModifyResponseVO;
import com.blws.domain.common.menu.vo.MenuRemoveRequestVO;
import com.blws.domain.common.menu.vo.MenuRemoveResponseVO;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@AllArgsConstructor
public class MenuService {

  private final MenuDAO menuDAO;

  public MainMenuListGetResponseVO getMainMenuList(
      final MainMenuListGetRequestVO mainMenuListGetRequestVO) {
    MenuEntity menuEntity = mainMenuListGetRequestVO.toEntity();
    List<MenuEntity> menuEntityList = menuDAO.selectMenuByConditions(menuEntity);
    return MainMenuListGetResponseVO.of(menuEntityList, mainMenuListGetRequestVO.getLocale());
  }

  public MenuListGetResponseVO getMenuList() throws MenuException {
    List<MenuEntity> menuEntityList = menuDAO.selectAll();
    return MenuListGetResponseVO.of(menuEntityList);
  }

  @Transactional
  public MenuAddResponseVO addMenu(final List<MenuAddRequestVO> menuAddRequestVO) {
    List<MenuEntity> menuEntityList =
        menuAddRequestVO.stream().map(MenuAddRequestVO::toEntity).collect(Collectors.toList());
    log.info(menuEntityList.toString());

    int addRows = menuDAO.insertMenuList(menuEntityList);
    return MenuAddResponseVO.of(addRows);
  }

  @Transactional
  public MenuModifyResponseVO modifyMenu(final List<MenuModifyRequestVO> menuModifyRequestVO) {
    List<MenuEntity> menuEntityList = menuModifyRequestVO.stream()
        .map(MenuModifyRequestVO::toEntity).collect(Collectors.toList());

    List<MenuEntity> updateList = new ArrayList<>();
    List<MenuEntity> insertList = new ArrayList<>();

    menuEntityList.forEach(menuEntity -> {
      if (isUpdate(menuEntity)) {
        updateList.add(menuEntity);
      } else {
        insertList.add(menuEntity);
      }
    });

    int upsertRows = (updateList.size() > 0 ? menuDAO.updateMenuById(updateList) : 0)
        + (insertList.size() > 0 ? menuDAO.insertMenuWithId(insertList) : 0)
            + menuDAO.updateMenuByParentsId(menuEntityList);

    log.info(menuEntityList.toString());
    return MenuModifyResponseVO.of(upsertRows);
  }

  private boolean isUpdate(MenuEntity targetEntity) {
    MenuEntity menuEntity = menuDAO.selectMenuById(targetEntity);
    return menuEntity != null;
  }

  @Transactional
  public MenuRemoveResponseVO removeMenu(List<MenuRemoveRequestVO> menuRemoveRequestVO) {
    List<MenuEntity> menuEntityList = menuRemoveRequestVO.stream()
        .map(MenuRemoveRequestVO::toEntity).collect(Collectors.toList());
    log.info(menuEntityList.toString());
    int deleteRows = menuDAO.deleteMenuById(menuEntityList);
    return MenuRemoveResponseVO.of(deleteRows);
  }

}
