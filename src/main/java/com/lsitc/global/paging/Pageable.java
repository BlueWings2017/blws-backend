package com.lsitc.global.paging;

import javax.validation.constraints.Positive;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public final class Pageable {

  @Positive(message = "페이지에는 양수만 입력할 수 있습니다.")
  private final Long page;

  @Positive(message = "사이즈에는 양수만 입력할 수 있습니다.")
  private final Long size;

  public Long getOffset() {
    return (page != null && size != null) ? (page - 1) * size : null;
  }
}
