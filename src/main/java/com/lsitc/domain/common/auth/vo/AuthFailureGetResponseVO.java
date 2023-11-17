package com.lsitc.domain.common.auth.vo;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import lombok.Builder;
import lombok.Getter;

@Getter
public class AuthFailureGetResponseVO {

  private final String message;

  @Builder
  private AuthFailureGetResponseVO(String message) {
    this.message = message;
  }

  public static AuthFailureGetResponseVO of(String message) {
    return builder().message(message).build();
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}
