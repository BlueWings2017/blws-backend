package com.lsitc.domain.common.dept.vo;

import com.lsitc.domain.common.dept.entity.DeptEntity;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.PositiveOrZero;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class DeptModifyRequestVO {

  @NotNull
  @PositiveOrZero(message = "음수의 ID는 사용할 수 없습니다.")
  private final long id;

  @NotBlank(message = "권한명이 필요합니다.")
  private final String name;
  
  @PositiveOrZero(message = "음수의 ID는 사용할 수 없습니다.")
  private final Long parentsId;

  private final String remark;

  public DeptEntity toEntity() {
    return DeptEntity.builder()
        .id(id)
        .name(name)
        .parentsId(parentsId)
        .remark(remark)
        .build();
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
    }
}
