package com.lsitc.domain.common.calendar.entity;

import java.time.LocalDate;
import java.time.LocalDateTime;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.lsitc.global.auditing.Auditable;
import com.lsitc.global.common.BaseAbstractEntity;
import com.lsitc.global.util.LocalDateUtils;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class CalendarEntity extends BaseAbstractEntity implements Auditable<Long, LocalDateTime> {

  private LocalDate date;
  private boolean isHoliday;
  private String holidayName;
  private String remark;


  @Builder
  private CalendarEntity(LocalDate date, boolean isHoliday, String holidayName, String remark) {
    this.date = date;
    this.isHoliday = isHoliday;
    this.holidayName = holidayName;
    this.remark = remark;
  }
  
  public LocalDate getStartDate() {
    return LocalDateUtils.getFirstDayOfMonth(date);
  }
  
  public LocalDate getEndDate() {
    return LocalDateUtils.getLastDayOfMonth(date);
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}
