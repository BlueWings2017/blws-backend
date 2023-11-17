package com.lsitc.domain.sample.vo;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import lombok.Builder;
import lombok.Getter;

@Getter
public class SampleAddResponseVO {

  @JsonInclude(Include.NON_EMPTY)
  private final String result;

  @JsonInclude(Include.NON_EMPTY)
  private final String id;

  @Builder
  private SampleAddResponseVO(String result, String id) {
    this.result = result;
    this.id = id;
  }

  public static SampleAddResponseVO of(final int addRows) {
    String result = 0 < addRows ? "success" : "failure";
    return builder().result(result).build();
  }

  public static SampleAddResponseVO of(final long id) {
    return builder()
        .id(String.valueOf(id))
        .build();
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}