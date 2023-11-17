package com.lsitc.domain.common.plan.entity;

import java.time.LocalDate;
import java.time.LocalDateTime;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.lsitc.global.auditing.Auditable;
import com.lsitc.global.common.BaseAbstractEntity;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class PlanEntity extends BaseAbstractEntity implements Auditable<Long, LocalDateTime> {
  private Long id;
  private LocalDate startDate;
  private String startHour;
  private String startMinute;
  private LocalDate endDate;
  private String endHour;
  private String endMinute;
  private String planTitle;
  private String planContents;
  private String planColor;

  @Builder
  private PlanEntity(Long id, LocalDate startDate, String startHour, String startMinute,
      LocalDate endDate, String endHour, String endMinute, String planTitle, String planContents,
      String planColor) {
    this.id = id;
    this.startDate = startDate;
    this.startHour = startHour;
    this.startMinute = startMinute;
    this.endDate = endDate;
    this.endHour = endHour;
    this.endMinute = endMinute;
    this.planTitle = planTitle;
    this.planContents = planContents;
    this.planColor = planColor;
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}
