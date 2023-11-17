package com.lsitc.domain.common.code.vo;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.lsitc.domain.common.code.entity.CodeEntity;
import javax.validation.constraints.NotNull;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import lombok.Getter;

@Getter
public class CodeRemoveRequestVO {

  @NotNull
  private final String commCdId;

  @JsonCreator
  public CodeRemoveRequestVO(String commCdId) {
    this.commCdId = commCdId;
  }

  public CodeEntity toEntity() {
    return CodeEntity.builder()
        .id(Long.valueOf(commCdId))
        .build();
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}
