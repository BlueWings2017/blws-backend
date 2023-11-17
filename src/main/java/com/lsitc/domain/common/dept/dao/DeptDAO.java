package com.lsitc.domain.common.dept.dao;

import com.lsitc.domain.common.dept.entity.DeptEntity;
import java.util.List;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface DeptDAO {

  DeptEntity selectDeptById(DeptEntity deptEntity);

  List<DeptEntity> selectAll();

  List<DeptEntity> selectDeptByConditions(DeptEntity deptEntity);

  int insertDept(List<DeptEntity> deptEntity);

  int updateDeptById(List<DeptEntity> deptEntity);

  int insertDeptWithId(List<DeptEntity> deptEntity);

  int deleteDeptById(List<DeptEntity> deptEntity);

  
}
