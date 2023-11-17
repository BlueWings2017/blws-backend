package com.lsitc.domain.common.calendar.vo;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.lsitc.domain.common.calendar.entity.CalendarEntity;
import com.lsitc.global.util.LocalDateUtils;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class CalendarSearchListGetRequestVO {
  private final String yyyymm;

  public CalendarEntity toEntity() {
    return CalendarEntity.builder()
        .date(LocalDateUtils.parseYyyymmdd(yyyymm + "01"))
        .build();
  }
  
  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}
