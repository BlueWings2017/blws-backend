package com.lsitc.domain.common.code.controller;

import com.lsitc.domain.common.code.exception.CodeException;
import com.lsitc.domain.common.code.service.CodeService;
import com.lsitc.domain.common.code.vo.GroupCodeAddRequestVO;
import com.lsitc.domain.common.code.vo.GroupCodeAddResponseVO;
import com.lsitc.domain.common.code.vo.GroupCodeModifyRequestVO;
import com.lsitc.domain.common.code.vo.GroupCodeModifyResponseVO;
import com.lsitc.domain.common.code.vo.GroupCodeRemoveRequestVO;
import com.lsitc.domain.common.code.vo.GroupCodeRemoveResponseVO;
import com.lsitc.domain.common.code.vo.GroupCodeListSearchRequestVO;
import com.lsitc.domain.common.code.vo.GroupCodeListSearchResponseVO;
import java.util.List;
import javax.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RequestMapping("/common/group-code")
@RestController
@RequiredArgsConstructor
public class GroupCodeController {

  private final CodeService codeService;

  @GetMapping("/search")
  public List<GroupCodeListSearchResponseVO> searchGroupCodeList(
      @Valid final GroupCodeListSearchRequestVO groupCodeListSearchRequestVO) throws CodeException {
    List<GroupCodeListSearchResponseVO> groupCodeListSearchGetResponseVO
        = codeService.searchGroupCodeList(groupCodeListSearchRequestVO);
    log.info(groupCodeListSearchGetResponseVO.toString());
    return groupCodeListSearchGetResponseVO;
  }

  @PostMapping
  public GroupCodeAddResponseVO addGroupCode(
      @RequestBody @Valid final List<GroupCodeAddRequestVO> groupCodeAddRequestVOList)
      throws CodeException {
    GroupCodeAddResponseVO groupCodeAddResponseVO = codeService.addGroupCode(
        groupCodeAddRequestVOList);
    log.info(groupCodeAddResponseVO.toString());
    return groupCodeAddResponseVO;
  }

  @PutMapping
  public GroupCodeModifyResponseVO modifyGroupCode(
      @RequestBody @Valid final List<GroupCodeModifyRequestVO> groupCodeModifyRequestVOList)
      throws CodeException {
    GroupCodeModifyResponseVO groupCodeModifyResponseVO = codeService.modifyGroupCode(
        groupCodeModifyRequestVOList);
    log.info(groupCodeModifyResponseVO.toString());
    return groupCodeModifyResponseVO;
  }

  @DeleteMapping
  public GroupCodeRemoveResponseVO removeGroupCode(
      @RequestBody @Valid final List<GroupCodeRemoveRequestVO> groupCodeRemoveRequestVOList)
      throws CodeException {
    GroupCodeRemoveResponseVO groupCodeRemoveResponseVO = codeService.removeGroupCode(
        groupCodeRemoveRequestVOList);
    log.info(groupCodeRemoveResponseVO.toString());
    return groupCodeRemoveResponseVO;
  }
}
