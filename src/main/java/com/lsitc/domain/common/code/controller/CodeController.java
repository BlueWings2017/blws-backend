package com.lsitc.domain.common.code.controller;

import com.lsitc.domain.common.code.exception.CodeException;
import com.lsitc.domain.common.code.service.CodeService;
import com.lsitc.domain.common.code.vo.CodeAddRequestVO;
import com.lsitc.domain.common.code.vo.CodeAddResponseVO;
import com.lsitc.domain.common.code.vo.CodeListSearchRequestVO;
import com.lsitc.domain.common.code.vo.CodeListSearchResponseVO;
import com.lsitc.domain.common.code.vo.CodeModifyRequestVO;
import com.lsitc.domain.common.code.vo.CodeModifyResponseVO;
import com.lsitc.domain.common.code.vo.CodeRemoveRequestVO;
import com.lsitc.domain.common.code.vo.CodeRemoveResponseVO;
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
@RequestMapping("/common/code")
@RestController
@RequiredArgsConstructor
public class CodeController {

  private final CodeService codeService;

  @GetMapping("/search")
  public List<CodeListSearchResponseVO> searchCodeList(
      @Valid final CodeListSearchRequestVO codeListSearchRequestVO) throws CodeException {
    List<CodeListSearchResponseVO> codeListSearchGetResponseVO
        = codeService.searchCodeList(codeListSearchRequestVO);
    log.info(codeListSearchGetResponseVO.toString());
    return codeListSearchGetResponseVO;
  }

  @PostMapping
  public CodeAddResponseVO addCode(
      @RequestBody @Valid final List<CodeAddRequestVO> codeListAddRequestVO)
      throws CodeException {
    CodeAddResponseVO codeAddResponseVO = codeService.addCode(codeListAddRequestVO);
    log.info(codeAddResponseVO.toString());
    return codeAddResponseVO;
  }

  @PutMapping
  public CodeModifyResponseVO modifyCode(
      @RequestBody @Valid final List<CodeModifyRequestVO> codeModifyRequestVOList)
      throws CodeException {
    CodeModifyResponseVO codeModifyResponseVO = codeService.modifyCode(
        codeModifyRequestVOList);
    log.info(codeModifyResponseVO.toString());
    return codeModifyResponseVO;
  }

  @DeleteMapping
  public CodeRemoveResponseVO removeCode(
      @RequestBody @Valid final List<CodeRemoveRequestVO> codeRemoveRequestVOList)
      throws CodeException {
    CodeRemoveResponseVO codeRemoveResponseVO = codeService.removeCode(
        codeRemoveRequestVOList);
    log.info(codeRemoveResponseVO.toString());
    return codeRemoveResponseVO;
  }
}
