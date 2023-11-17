package com.lsitc.domain.common.dept.vo;

import com.lsitc.domain.common.dept.entity.DeptEntity;
import javax.validation.constraints.NotBlank;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class DeptAddRequestVO {

  @NotBlank(message = "권한명이 필요합니다.")
  private final String name;
  private final String remark;
  private final Long parentsId;

  public DeptEntity toEntity() {
    return DeptEntity.builder()
        .name(name)
        .remark(remark)
        .parentsId(parentsId)
        .build();
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}
