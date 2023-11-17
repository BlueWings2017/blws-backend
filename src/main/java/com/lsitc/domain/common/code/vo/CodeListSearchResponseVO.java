package com.lsitc.domain.common.code.vo;

import java.time.LocalDateTime;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.lsitc.domain.common.code.entity.CodeEntity;
import com.lsitc.domain.common.code.entity.GroupCodeEntity;
import com.lsitc.domain.model.BooleanState;
import lombok.Builder;
import lombok.Getter;

@Getter
public class CodeListSearchResponseVO {

  private final String commCdId;
  private final String commGrpCdId;
  private final String commGrpCd;
  private final String commCd;
  private final String commCdNm;
  private final String sortSeq;
  private final String useFg;
  private final String rmrk;
  private final Long regUserNo;
  private final LocalDateTime regDttm;
  private final Long procUserNo;
  private final LocalDateTime procDttm;

  @Builder
  private CodeListSearchResponseVO(String commCdId, String commGrpCdId, String commGrpCd,
      String commCd, String commCdNm, String sortSeq, String useFg, String rmrk, Long regUserNo,
      LocalDateTime regDttm, Long procUserNo, LocalDateTime procDttm) {
    this.commCdId = commCdId;
    this.commGrpCdId = commGrpCdId;
    this.commGrpCd = commGrpCd;
    this.commCd = commCd;
    this.commCdNm = commCdNm;
    this.sortSeq = sortSeq;
    this.useFg = useFg;
    this.rmrk = rmrk;
    this.regUserNo = regUserNo;
    this.regDttm = regDttm;
    this.procUserNo = procUserNo;
    this.procDttm = procDttm;
  }

  public static CodeListSearchResponseVO of(CodeEntity codeEntity,
      GroupCodeEntity groupCodeEntity) {
    return builder()
        .commCdId(String.valueOf(codeEntity.getId()))
        .commCd(codeEntity.getCode())
        .commCdNm(codeEntity.getName())
        .commGrpCdId(String.valueOf(codeEntity.getGroupCodeId()))
        .commGrpCd(groupCodeEntity.getCode())
        .sortSeq(String.valueOf(codeEntity.getSortSequence()))
        .useFg(convertBoolean(codeEntity.isUsed()))
        .rmrk(codeEntity.getRemark())
        .regUserNo(codeEntity.getCreatedBy())
        .regDttm(codeEntity.getCreatedDate())
        .procUserNo(codeEntity.getLastModifiedBy())
        .procDttm(codeEntity.getLastModifiedDate())
        .build();
  }

  private static String convertBoolean(Boolean booleanValue) {
    return BooleanState.of(booleanValue).getStringValue();
  }
  
  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}
