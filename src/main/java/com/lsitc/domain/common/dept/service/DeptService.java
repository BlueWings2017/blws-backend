package com.lsitc.domain.common.dept.service;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.lsitc.domain.common.dept.dao.DeptDAO;
import com.lsitc.domain.common.dept.entity.DeptEntity;
import com.lsitc.domain.common.dept.exception.DeptException;
import com.lsitc.domain.common.dept.vo.DeptAddRequestVO;
import com.lsitc.domain.common.dept.vo.DeptAddResponseVO;
import com.lsitc.domain.common.dept.vo.DeptListGetResponseVO;
import com.lsitc.domain.common.dept.vo.DeptModifyRequestVO;
import com.lsitc.domain.common.dept.vo.DeptModifyResponseVO;
import com.lsitc.domain.common.dept.vo.DeptRemoveRequestVO;
import com.lsitc.domain.common.dept.vo.DeptRemoveResponseVO;
import com.lsitc.domain.common.dept.vo.DeptSearchListGetRequestVO;
import com.lsitc.domain.common.dept.vo.DeptSearchListGetResponseVO;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@AllArgsConstructor
public class DeptService {

  private final DeptDAO deptDAO;

  public List<DeptListGetResponseVO> getDeptList() {
    List<DeptEntity> deptEntityList = deptDAO.selectAll();
    return deptEntityList.stream().map(DeptListGetResponseVO::of).collect(Collectors.toList());
  }
  
  public List<DeptSearchListGetResponseVO> searchDeptList(DeptSearchListGetRequestVO deptSearchListGetRequestVO) {
    DeptEntity deptEntity = deptSearchListGetRequestVO.toEntity();
    List<DeptEntity> deptEntityList = deptDAO.selectDeptByConditions(deptEntity);
    return deptEntityList.stream().map(DeptSearchListGetResponseVO::of).collect(Collectors.toList());
  }

  @Transactional
  public DeptAddResponseVO addDept(final List<DeptAddRequestVO> deptAddRequestVO) {
    List<DeptEntity> deptEntityList =
        deptAddRequestVO.stream().map(DeptAddRequestVO::toEntity).collect(Collectors.toList());
    log.info(deptEntityList.toString());
    int addRows = deptDAO.insertDept(deptEntityList);
    return DeptAddResponseVO.of(addRows);
  }

  @Transactional
  public DeptModifyResponseVO modifyDept(final List<DeptModifyRequestVO> deptModifyRequestVO) {
    List<DeptEntity> deptEntityList = deptModifyRequestVO.stream()
        .map(DeptModifyRequestVO::toEntity).collect(Collectors.toList());

    List<DeptEntity> updateList = new ArrayList<>();
    List<DeptEntity> insertList = new ArrayList<>();

    deptEntityList.forEach(deptEntity -> {
      if (isUpdate(deptEntity)) {
        updateList.add(deptEntity);
      } else {
        insertList.add(deptEntity);
      }
    });

    int upsertRows = (updateList.size() > 0 ? deptDAO.updateDeptById(updateList) : 0)
        + (insertList.size() > 0 ? deptDAO.insertDeptWithId(insertList) : 0);

    log.info(deptEntityList.toString());
    return DeptModifyResponseVO.of(upsertRows);
  }

  private boolean isUpdate(DeptEntity targetEntity) {
    DeptEntity deptEntity = deptDAO.selectDeptById(targetEntity);
    return deptEntity != null;
  }

  @Transactional
  public DeptRemoveResponseVO removeDept(final List<DeptRemoveRequestVO> deptRemoveRequestVO)
      throws DeptException {
    List<DeptEntity> deptEntityList = deptRemoveRequestVO.stream()
        .map(DeptRemoveRequestVO::toEntity).collect(Collectors.toList());
    log.info(deptEntityList.toString());
    int deleteRows = deptDAO.deleteDeptById(deptEntityList);
    return DeptRemoveResponseVO.of(deleteRows);
  }
}
