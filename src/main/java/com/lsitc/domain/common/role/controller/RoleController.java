package com.lsitc.domain.common.role.controller;

import java.util.List;
import javax.validation.Valid;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.lsitc.domain.common.role.exception.RoleException;
import com.lsitc.domain.common.role.service.RoleService;
import com.lsitc.domain.common.role.vo.RoleAddRequestVO;
import com.lsitc.domain.common.role.vo.RoleAddResponseVO;
import com.lsitc.domain.common.role.vo.RoleListGetResponseVO;
import com.lsitc.domain.common.role.vo.RoleModifyRequestVO;
import com.lsitc.domain.common.role.vo.RoleModifyResponseVO;
import com.lsitc.domain.common.role.vo.RoleRemoveRequestVO;
import com.lsitc.domain.common.role.vo.RoleRemoveResponseVO;
import com.lsitc.domain.common.role.vo.RoleSearchListGetRequestVO;
import com.lsitc.domain.common.role.vo.RoleSearchListGetResponseVO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequestMapping("/common/role")
@RestController
@RequiredArgsConstructor
public class RoleController {

  private final RoleService roleService;

  @GetMapping("/list")
  public List<RoleListGetResponseVO> getRoleList() throws RoleException {
    List<RoleListGetResponseVO> roleListGetResponseVOList = roleService.getRoleList();
    log.info(roleListGetResponseVOList.toString());
    return roleListGetResponseVOList;
  }

  @GetMapping("/search")
  public List<RoleSearchListGetResponseVO> searchRoleList(
      @Valid final RoleSearchListGetRequestVO roleInfoGetRequestVO) throws RoleException {
    List<RoleSearchListGetResponseVO> roleListGetResponseVOList =
        roleService.searchRoleList(roleInfoGetRequestVO);
    log.info(roleListGetResponseVOList.toString());
    return roleListGetResponseVOList;
  }

  @PostMapping
  public RoleAddResponseVO addRoleList(
      @RequestBody @Valid final List<RoleAddRequestVO> roleListAddRequestVO)
      throws RoleException {
    log.info(roleListAddRequestVO.toString());
    RoleAddResponseVO roleListAddResponseVO = roleService.addRoleList(roleListAddRequestVO);
    log.info(roleListAddResponseVO.toString());
    return roleListAddResponseVO;
  }

  @PutMapping
  public RoleModifyResponseVO modifyRoleList(
      @RequestBody @Valid final List<RoleModifyRequestVO> roleListModifyRequestVO)
      throws RoleException {
    log.info(roleListModifyRequestVO.toString());
    RoleModifyResponseVO roleListModifyResponseVO =
        roleService.modifyRoleList(roleListModifyRequestVO);
    log.info(roleListModifyResponseVO.toString());
    return roleListModifyResponseVO;
  }

  @DeleteMapping
  public RoleRemoveResponseVO removeRoleList(
      @RequestBody @Valid final List<RoleRemoveRequestVO> roleListRemoveRequestVO)
      throws RoleException {
    log.info(roleListRemoveRequestVO.toString());
    RoleRemoveResponseVO roleListRemoveResponseVO =
        roleService.removeRoleList(roleListRemoveRequestVO);
    log.info(roleListRemoveResponseVO.toString());
    return roleListRemoveResponseVO;
  }

}
