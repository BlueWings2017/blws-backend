package com.lsitc.domain.common.plan.service;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.lsitc.domain.common.plan.dao.PlanDAO;
import com.lsitc.domain.common.plan.entity.PlanEntity;
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
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@AllArgsConstructor
public class PlanService {

  private final PlanDAO planDAO;

  public PlanInfoGetResponseVO searchPlanList(final PlanInfoGetRequestVO planInfoGetRequestVO) {
    PlanEntity planEntity = planInfoGetRequestVO.toEntity();
    log.info(planEntity.toString());
    PlanEntity resultEntity = planDAO.selectPlanById(planEntity);
    return PlanInfoGetResponseVO.of(resultEntity);
  }
  
  public List<PlanSearchListGetResponseVO> searchPlanList(
      final PlanSearchListGetRequestVO planSearchListGetRequestVO) {
    PlanEntity planEntity = planSearchListGetRequestVO.toEntity();
    log.info(planEntity.toString());

    List<PlanEntity> planEntityList = planDAO.selectPlanByConditions(planEntity);
    log.info(planEntityList.toString());

    return PlanSearchListGetResponseVO.of(planEntityList);
  }
  
  @Transactional
  public PlanAddResponseVO addPlan(final List<PlanAddRequestVO> planAddRequestVO) {
    List<PlanEntity> planEntityList =
        planAddRequestVO.stream().map(PlanAddRequestVO::toEntity).collect(Collectors.toList());
    log.info(planEntityList.toString());

    int addRows = planDAO.insertPlanList(planEntityList);
    return PlanAddResponseVO.of(addRows);
  }

  public PlanModifyResponseVO modifyPlan(final List<PlanModifyRequestVO> planModifyRequestVO) {
    List<PlanEntity> planEntityList = planModifyRequestVO.stream()
        .map(PlanModifyRequestVO::toEntity).collect(Collectors.toList());

    List<PlanEntity> updateList = new ArrayList<>();
    List<PlanEntity> insertList = new ArrayList<>();

    planEntityList.forEach(planEntity -> {
      if (isUpdate(planEntity)) {
        updateList.add(planEntity);
      } else {
        insertList.add(planEntity);
      }
    });

    int upsertRows = (updateList.size() > 0 ? planDAO.updatePlanById(updateList) : 0)
        + (insertList.size() > 0 ? planDAO.insertPlanWithId(insertList) : 0);

    log.info(planEntityList.toString());
    return PlanModifyResponseVO.of(upsertRows);
  }
  
  private boolean isUpdate(PlanEntity targetEntity) {
    PlanEntity planEntity = planDAO.selectPlanById(targetEntity);
    return planEntity != null;
  }

  public PlanRemoveResponseVO removePlan(final List<PlanRemoveRequestVO> planRemoveRequestVO) {
    List<PlanEntity> planEntityList = planRemoveRequestVO.stream()
        .map(PlanRemoveRequestVO::toEntity).collect(Collectors.toList());
    log.info(planEntityList.toString());
    int deleteRows = planDAO.deletePlanById(planEntityList);
    return PlanRemoveResponseVO.of(deleteRows);
  }

}
