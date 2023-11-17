package com.lsitc.domain.common.role.vo;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import lombok.Builder;
import lombok.Getter;

@Getter
public class RoleAddResponseVO {

  private final String result;

  @Builder
  private RoleAddResponseVO(String result) {
    this.result = result;
  }

  public static RoleAddResponseVO of(final int tryRow, final int addRows) {
    String result = tryRow == addRows ? "success" : "failure";
    return builder().result(result).build();
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}
