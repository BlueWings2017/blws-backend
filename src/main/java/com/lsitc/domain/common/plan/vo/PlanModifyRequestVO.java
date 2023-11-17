package com.lsitc.domain.common.plan.vo;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.lsitc.domain.common.plan.entity.PlanEntity;
import com.lsitc.global.util.LocalDateUtils;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class PlanModifyRequestVO {
  
  private final String planSeq;
  private final String strtDt;
  private final String strtHh;
  private final String strtMm;
  private final String endDt;
  private final String endHh;
  private final String endMm;
  private final String planTitle;
  private final String planCntn;
  private final String planColor;
  
  public PlanEntity toEntity() {
    return PlanEntity.builder()
        .id(Long.valueOf(planSeq))
        .startDate(LocalDateUtils.parse(strtDt, "yyyy-MM-dd"))
        .startHour(strtHh)
        .startMinute(strtMm)
        .endDate(LocalDateUtils.parse(endDt, "yyyy-MM-dd"))
        .endHour(endHh)
        .endMinute(endMm)
        .planTitle(planTitle)
        .planContents(planCntn)
        .planColor(planColor)
        .build();
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}
