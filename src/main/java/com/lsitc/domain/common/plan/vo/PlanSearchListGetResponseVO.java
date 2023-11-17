package com.lsitc.domain.common.plan.vo;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.lsitc.domain.common.plan.entity.PlanEntity;
import lombok.Builder;
import lombok.Getter;

@Getter
public class PlanSearchListGetResponseVO {
  
  private final LocalDate dt;
  private final Long planSeq;
  private final LocalDate strtDt;
  private final LocalDate endDt;
  private final String planTitle;
  private final String planColor;
  private final Long regUserNo;
  private final LocalDateTime regDttm;
  private final Long procUserNo;
  private final LocalDateTime procDttm;

  @Builder
  private PlanSearchListGetResponseVO(LocalDate dt, Long planSeq, LocalDate strtDt, LocalDate endDt,
      String planTitle, String planColor, Long regUserNo, LocalDateTime regDttm, Long procUserNo,
      LocalDateTime procDttm) {
    this.dt = dt;
    this.planSeq = planSeq;
    this.strtDt = strtDt;
    this.endDt = endDt;
    this.planTitle = planTitle;
    this.planColor = planColor;
    this.regUserNo = regUserNo;
    this.regDttm = regDttm;
    this.procUserNo = procUserNo;
    this.procDttm = procDttm;
  }

  public static List<PlanSearchListGetResponseVO> of(List<PlanEntity> planEntityList) {
    List<PlanSearchListGetResponseVO> resultList = new ArrayList<PlanSearchListGetResponseVO>();
    
    planEntityList.forEach(entity -> {
      
      for ( LocalDate date = entity.getStartDate();
            date.isBefore(entity.getEndDate().plusDays(1));
            date = date.plusDays(1) ) {
        PlanSearchListGetResponseVO vo = PlanSearchListGetResponseVO.builder()
        .dt(date)
        .planSeq(entity.getId())
        .strtDt(entity.getStartDate())
        .endDt(entity.getEndDate())
        .planTitle(entity.getPlanTitle())
        .planColor(entity.getPlanColor())
        .regUserNo(entity.getCreatedBy())
        .regDttm(entity.getCreatedDate())
        .procUserNo(entity.getLastModifiedBy())
        .procDttm(entity.getLastModifiedDate())
        .build();
        
        resultList.add(vo);
      }
      
    });
    
    return resultList;
  }
  
  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }

}
