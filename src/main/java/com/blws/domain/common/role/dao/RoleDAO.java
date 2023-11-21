package com.blws.domain.common.role.dao;

import java.util.List;
import org.apache.ibatis.annotations.Mapper;

import com.blws.domain.common.role.entity.RoleEntity;

@Mapper
public interface RoleDAO {
  
  RoleEntity selectRoleById(RoleEntity roleEntity);

  List<RoleEntity> selectAll();
  
  List<RoleEntity> selectRoleByConditions(RoleEntity roleEntity);

  int insertRoleList(List<RoleEntity> roleEntityList);

  int updateRoleById(List<RoleEntity> roleEntity);

  int insertRoleWithId(List<RoleEntity> roleEntity);

  int deleteRoleById(List<RoleEntity> roleEntity);
}
