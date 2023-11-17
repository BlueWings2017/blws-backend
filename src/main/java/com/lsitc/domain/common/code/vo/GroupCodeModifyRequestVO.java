package com.lsitc.domain.common.code.vo;

import com.lsitc.domain.common.code.entity.GroupCodeEntity;
import com.lsitc.domain.model.BooleanState;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.PositiveOrZero;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class GroupCodeModifyRequestVO {

  @NotNull
  @PositiveOrZero(message = "음수의 ID는 사용할 수 없습니다.")
  private final String commGrpCdId;

  @NotBlank(message = "공통 코드가 필요합니다.")
  private final String commGrpCd;

  private final String commGrpNm;

  private final String useFg;

  private final String rmrk;

  public GroupCodeEntity toEntity() {
    return GroupCodeEntity.builder()
        .id(Long.valueOf(commGrpCdId))
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
