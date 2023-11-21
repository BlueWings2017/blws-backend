package com.blws.domain.common.auth.vo;

import lombok.Builder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@Builder
@AllArgsConstructor
public class AuthFailureGetRequestVO {

  private final String userId;
  private final String password;

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}
