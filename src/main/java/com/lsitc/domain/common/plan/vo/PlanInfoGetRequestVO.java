package com.lsitc.domain.common.plan.vo;

import javax.validation.constraints.NotNull;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.lsitc.domain.common.plan.entity.PlanEntity;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class PlanInfoGetRequestVO {

  @NotNull
  private final String planSeq;

  public PlanEntity toEntity() {
    return PlanEntity.builder().id(Long.valueOf(planSeq)).build();
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }

}
