package com.lsitc.domain.common.role.dao;

import com.lsitc.domain.common.role.entity.RoleEntity;
import java.util.List;
import org.apache.ibatis.annotations.Mapper;

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
