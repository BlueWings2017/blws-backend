package com.lsitc.domain.common.role.service;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.lsitc.domain.common.role.dao.RoleDAO;
import com.lsitc.domain.common.role.entity.RoleEntity;
import com.lsitc.domain.common.role.exception.RoleException;
import com.lsitc.domain.common.role.vo.RoleAddRequestVO;
import com.lsitc.domain.common.role.vo.RoleAddResponseVO;
import com.lsitc.domain.common.role.vo.RoleListGetResponseVO;
import com.lsitc.domain.common.role.vo.RoleModifyRequestVO;
import com.lsitc.domain.common.role.vo.RoleModifyResponseVO;
import com.lsitc.domain.common.role.vo.RoleRemoveRequestVO;
import com.lsitc.domain.common.role.vo.RoleRemoveResponseVO;
import com.lsitc.domain.common.role.vo.RoleSearchListGetRequestVO;
import com.lsitc.domain.common.role.vo.RoleSearchListGetResponseVO;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@AllArgsConstructor
public class RoleService {

  private final RoleDAO roleDAO;

  public List<RoleListGetResponseVO> getRoleList() {
    List<RoleEntity> roleEntityList = roleDAO.selectAll();
    return roleEntityList.stream().map(RoleListGetResponseVO::of).collect(Collectors.toList());
  }

  public List<RoleSearchListGetResponseVO> searchRoleList(
      final RoleSearchListGetRequestVO roleInfoGetRequestVO) {
    RoleEntity roleEntity = roleInfoGetRequestVO.toEntity();
    log.info(roleEntity.toString());
    List<RoleEntity> roleEntityList = roleDAO.selectRoleByConditions(roleEntity);
    return roleEntityList.stream().map(RoleSearchListGetResponseVO::of)
        .collect(Collectors.toList());
  }

  @Transactional
  public RoleAddResponseVO addRoleList(final List<RoleAddRequestVO> roleAddRequestVO) {
    List<RoleEntity> roleEntityList = roleAddRequestVO.stream()
        .map(RoleAddRequestVO::toEntity).collect(Collectors.toList());
    log.info(roleEntityList.toString());
    int addRows = roleDAO.insertRoleList(roleEntityList);
    return RoleAddResponseVO.of(roleEntityList.size(), addRows);
  }

  @Transactional
  public RoleModifyResponseVO modifyRoleList(
      final List<RoleModifyRequestVO> roleModifyRequestVO) {
    List<RoleEntity> roleEntityList = roleModifyRequestVO.stream()
        .map(RoleModifyRequestVO::toEntity).collect(Collectors.toList());

    List<RoleEntity> updateList = new ArrayList<>();
    List<RoleEntity> insertList = new ArrayList<>();

    roleEntityList.forEach(roleEntity -> {
      if (isUpdate(roleEntity)) {
        updateList.add(roleEntity);
      } else {
        insertList.add(roleEntity);
      }
    });

    int upsertRows = (updateList.size() > 0 ? roleDAO.updateRoleById(updateList) : 0)
        + (insertList.size() > 0 ? roleDAO.insertRoleWithId(insertList) : 0);

    log.info(roleEntityList.toString());
    return RoleModifyResponseVO.of(upsertRows);
  }

  private boolean isUpdate(RoleEntity targetEntity) {
    RoleEntity roleEntity = roleDAO.selectRoleById(targetEntity);
    return roleEntity != null;
  }

  @Transactional
  public RoleRemoveResponseVO removeRoleList(
      final List<RoleRemoveRequestVO> roleRemoveRequestVO) throws RoleException {
    List<RoleEntity> roleEntityList = roleRemoveRequestVO.stream()
        .map(RoleRemoveRequestVO::toEntity).collect(Collectors.toList());
    log.info(roleEntityList.toString());
    int deleteRows = roleDAO.deleteRoleById(roleEntityList);
    return RoleRemoveResponseVO.of(deleteRows);
  }
}
