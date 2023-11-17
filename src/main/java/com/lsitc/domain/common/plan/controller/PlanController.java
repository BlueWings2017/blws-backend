package com.lsitc.domain.common.plan.controller;

import java.util.List;
import javax.validation.Valid;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.lsitc.domain.common.plan.exception.PlanException;
import com.lsitc.domain.common.plan.service.PlanService;
import com.lsitc.domain.common.plan.vo.PlanAddRequestVO;
import com.lsitc.domain.common.plan.vo.PlanAddResponseVO;
import com.lsitc.domain.common.plan.vo.PlanInfoGetRequestVO;
import com.lsitc.domain.common.plan.vo.PlanInfoGetResponseVO;
import com.lsitc.domain.common.plan.vo.PlanModifyRequestVO;
import com.lsitc.domain.common.plan.vo.PlanModifyResponseVO;
import com.lsitc.domain.common.plan.vo.PlanRemoveRequestVO;
import com.lsitc.domain.common.plan.vo.PlanRemoveResponseVO;
import com.lsitc.domain.common.plan.vo.PlanSearchListGetRequestVO;
import com.lsitc.domain.common.plan.vo.PlanSearchListGetResponseVO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequestMapping("/common/plan")
@RestController
@RequiredArgsConstructor
public class PlanController {

  private final PlanService planService;

  @GetMapping("/info")
  public PlanInfoGetResponseVO getPlanList(@Valid final PlanInfoGetRequestVO planInfoGetRequestVO) {
    log.info(planInfoGetRequestVO.toString());
    PlanInfoGetResponseVO planInfoGetResponseVO = planService.searchPlanList(planInfoGetRequestVO);
    log.info(planInfoGetResponseVO.toString());
    return planInfoGetResponseVO;
  }

  @GetMapping("/search")
  public List<PlanSearchListGetResponseVO> searchPlanList(
      @Valid final PlanSearchListGetRequestVO planSearchListGetRequestVO) {
    log.info(planSearchListGetRequestVO.toString());
    List<PlanSearchListGetResponseVO> planSearchListGetResponseVO =
        planService.searchPlanList(planSearchListGetRequestVO);
    log.info(planSearchListGetResponseVO.toString());
    return planSearchListGetResponseVO;
  }

  @PostMapping
  public PlanAddResponseVO addPlan(
      @RequestBody @Valid final List<PlanAddRequestVO> planAddRequestVO) throws PlanException {
    log.info(planAddRequestVO.toString());
    PlanAddResponseVO planAddResponseVO = planService.addPlan(planAddRequestVO);
    log.info(planAddResponseVO.toString());
    return planAddResponseVO;
  }

  @PutMapping
  public PlanModifyResponseVO modifyPlan(
      @RequestBody @Valid final List<PlanModifyRequestVO> planModifyRequestVO)
      throws PlanException {
    log.info(planModifyRequestVO.toString());
    PlanModifyResponseVO planModifyResponseVO = planService.modifyPlan(planModifyRequestVO);
    log.info(planModifyResponseVO.toString());
    return planModifyResponseVO;
  }

  @DeleteMapping
  public PlanRemoveResponseVO removePlan(
      @RequestBody @Valid final List<PlanRemoveRequestVO> planRemoveRequestVO)
      throws PlanException {
    log.info(planRemoveRequestVO.toString());
    PlanRemoveResponseVO planRemoveResponseVO = planService.removePlan(planRemoveRequestVO);
    log.info(planRemoveResponseVO.toString());
    return planRemoveResponseVO;
  }
}
