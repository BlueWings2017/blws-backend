package com.lsitc.domain.common.bloc.controller;

import com.lsitc.domain.common.bloc.exception.BlocException;
import com.lsitc.domain.common.bloc.service.BlocService;
import com.lsitc.domain.common.bloc.vo.BlocAddRequestVO;
import com.lsitc.domain.common.bloc.vo.BlocAddResponseVO;
import com.lsitc.domain.common.bloc.vo.BlocInfoGetRequestVO;
import com.lsitc.domain.common.bloc.vo.BlocInfoGetResponseVO;
import com.lsitc.domain.common.bloc.vo.BlocListGetResponseVO;
import com.lsitc.domain.common.bloc.vo.BlocModifyRequestVO;
import com.lsitc.domain.common.bloc.vo.BlocModifyResponseVO;
import com.lsitc.domain.common.bloc.vo.BlocRemoveRequestVO;
import com.lsitc.domain.common.bloc.vo.BlocRemoveResponseVO;
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
@RequestMapping("/common/bloc")
@RestController
@RequiredArgsConstructor
public class BlocController {

  private final BlocService blocService;

  @GetMapping("/info")
  public BlocInfoGetResponseVO getBlocInfo(@Valid final BlocInfoGetRequestVO blocInfoGetRequestVO)
      throws BlocException {
    log.info(blocInfoGetRequestVO.toString());
    BlocInfoGetResponseVO blocInfoGetResponseVO = blocService.getBlocInfo(blocInfoGetRequestVO);
    log.info(blocInfoGetResponseVO.toString());
    return blocInfoGetResponseVO;
  }

  @GetMapping("/list")
  public List<BlocListGetResponseVO> getBlocList() throws BlocException {
    List<BlocListGetResponseVO> blocListGetResponseVOList = blocService.getBlocList();
    log.info(blocListGetResponseVOList.toString());
    return blocListGetResponseVOList;
  }

  @PostMapping("")
  public BlocAddResponseVO addBloc(@RequestBody @Valid final BlocAddRequestVO blocAddRequestVO)
      throws BlocException {
    log.info(blocAddRequestVO.toString());
    BlocAddResponseVO blocAddResponseVO = blocService.addBloc(blocAddRequestVO);
    log.info(blocAddResponseVO.toString());
    return blocAddResponseVO;
  }

  @PutMapping("")
  public BlocModifyResponseVO modifyBloc(
      @RequestBody @Valid final BlocModifyRequestVO blocModifyRequestVO)
      throws BlocException {
    log.info(blocModifyRequestVO.toString());
    BlocModifyResponseVO blocModifyResponseVO = blocService.modifyBloc(blocModifyRequestVO);
    log.info(blocModifyResponseVO.toString());
    return blocModifyResponseVO;
  }

  @DeleteMapping("")
  public BlocRemoveResponseVO removeBloc(@Valid final BlocRemoveRequestVO blocRemoveRequestVO)
      throws BlocException {
    log.info(blocRemoveRequestVO.toString());
    BlocRemoveResponseVO blocRemoveResponseVO = blocService.removeBloc(
        blocRemoveRequestVO);
    log.info(blocRemoveResponseVO.toString());
    return blocRemoveResponseVO;
  }
}
