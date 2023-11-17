package com.lsitc.domain.common.dept.vo;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import lombok.Builder;
import lombok.Getter;

@Getter
public class DeptModifyResponseVO {

  private final String result;

  @Builder
  private DeptModifyResponseVO(String result) {
    this.result = result;
  }

  public static DeptModifyResponseVO of(int upsertRows) {
    String result = 0 < upsertRows ? "success" : "failure";
    return builder().result(result).build();
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
    }
}
