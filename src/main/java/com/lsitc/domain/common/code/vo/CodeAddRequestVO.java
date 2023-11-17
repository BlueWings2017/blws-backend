package com.lsitc.domain.common.code.vo;

import com.lsitc.domain.common.code.entity.CodeEntity;
import com.lsitc.domain.model.BooleanState;
import javax.validation.constraints.NotBlank;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class CodeAddRequestVO {

  @NotBlank(message = "그룹 코드가 필요합니다.")
  private final String commGrpCdId;
  @NotBlank(message = "코드가 필요합니다.")
  private final String commCd;
  private final String commCdNm;
  private final String sortSeq;
  private final String useFg;
  private final String rmrk;

  public CodeEntity toEntity() {
    return CodeEntity.builder()
        .groupCodeId(Long.valueOf(commGrpCdId))
        .code(commCd)
        .name(commCdNm)
        .sortSequence(Long.valueOf(sortSeq))
        .isUsed(convertUseFg())
        .remark(rmrk)
        .build();
  }

  private Boolean convertUseFg() {
    return BooleanState.of(String.valueOf(this.useFg)).getBooleanValue();
  }
  
  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}
