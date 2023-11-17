package com.lsitc.domain.common.dept.controller;

import java.util.List;
import javax.validation.Valid;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.lsitc.domain.common.dept.exception.DeptException;
import com.lsitc.domain.common.dept.service.DeptService;
import com.lsitc.domain.common.dept.vo.DeptAddRequestVO;
import com.lsitc.domain.common.dept.vo.DeptAddResponseVO;
import com.lsitc.domain.common.dept.vo.DeptListGetResponseVO;
import com.lsitc.domain.common.dept.vo.DeptModifyRequestVO;
import com.lsitc.domain.common.dept.vo.DeptModifyResponseVO;
import com.lsitc.domain.common.dept.vo.DeptRemoveRequestVO;
import com.lsitc.domain.common.dept.vo.DeptRemoveResponseVO;
import com.lsitc.domain.common.dept.vo.DeptSearchListGetRequestVO;
import com.lsitc.domain.common.dept.vo.DeptSearchListGetResponseVO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequestMapping("/common/dept")
@RestController
@RequiredArgsConstructor
public class DeptController {

  private final DeptService deptService;

  @GetMapping("/list")
  public List<DeptListGetResponseVO> getDeptList() throws DeptException {
    List<DeptListGetResponseVO> deptListGetResponseVOList = deptService.getDeptList();
    log.info(deptListGetResponseVOList.toString());
    return deptListGetResponseVOList;
  }

  @GetMapping("/search")
  public List<DeptSearchListGetResponseVO> searchDeptList(
      @Valid final DeptSearchListGetRequestVO deptSearchListGetRequestVO) throws DeptException {
    log.info(deptSearchListGetRequestVO.toString());
    List<DeptSearchListGetResponseVO> deptSearchListGetResponseVO =
        deptService.searchDeptList(deptSearchListGetRequestVO);
    log.info(deptSearchListGetResponseVO.toString());
    return deptSearchListGetResponseVO;
  }

  @PostMapping
  public DeptAddResponseVO addDept(
      @RequestBody @Valid final List<DeptAddRequestVO> deptAddRequestVO) throws DeptException {
    log.info(deptAddRequestVO.toString());
    DeptAddResponseVO deptAddResponseVO = deptService.addDept(deptAddRequestVO);
    log.info(deptAddResponseVO.toString());
    return deptAddResponseVO;
  }

  @PutMapping
  public DeptModifyResponseVO modifyDept(
      @RequestBody @Valid final List<DeptModifyRequestVO> deptModifyRequestVO)
      throws DeptException {
    log.info(deptModifyRequestVO.toString());
    DeptModifyResponseVO deptModifyResponseVO = deptService.modifyDept(deptModifyRequestVO);
    log.info(deptModifyResponseVO.toString());
    return deptModifyResponseVO;
  }

  @DeleteMapping
  public DeptRemoveResponseVO removeDept(
      @RequestBody @Valid final List<DeptRemoveRequestVO> deptRemoveRequestVO)
      throws DeptException {
    log.info(deptRemoveRequestVO.toString());
    DeptRemoveResponseVO deptRemoveResponseVO = deptService.removeDept(deptRemoveRequestVO);
    log.info(deptRemoveResponseVO.toString());
    return deptRemoveResponseVO;
  }
}
