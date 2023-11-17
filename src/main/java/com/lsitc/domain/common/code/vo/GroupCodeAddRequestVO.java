package com.lsitc.domain.common.code.vo;

import com.lsitc.domain.common.code.entity.GroupCodeEntity;
import com.lsitc.domain.model.BooleanState;
import javax.validation.constraints.NotBlank;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class GroupCodeAddRequestVO {

  @NotBlank(message = "사업장명이 필요합니다.")
  private final String commGrpCd;

  private final String commGrpNm;

  private final String useFg;

  private String rmrk;

  public GroupCodeEntity toEntity() {
    return GroupCodeEntity.builder()
        .code(commGrpCd)
        .name(commGrpNm)
        .isUsed(convertUseFg())
        .remark(rmrk)
        .build();
  }

  private Boolean convertUseFg() {
    return BooleanState.of(this.useFg).getBooleanValue();
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}
