package com.lsitc.domain.common.code.vo;

import java.time.LocalDateTime;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.lsitc.domain.common.code.entity.GroupCodeEntity;
import com.lsitc.domain.model.BooleanState;
import lombok.Builder;
import lombok.Getter;

@Getter
public class GroupCodeListSearchResponseVO {

  private final String commGrpCdId;
  private final String commGrpCd;
  private final String commGrpNm;
  private final String useFg;
  private final String rmrk;
  private final Long regUserNo;
  private final LocalDateTime regDttm;
  private final Long procUserNo;
  private final LocalDateTime procDttm;

  @Builder
  private GroupCodeListSearchResponseVO(String commGrpCdId, String commGrpCd, String commGrpNm,
      String useFg, String rmrk, Long regUserNo, LocalDateTime regDttm, Long procUserNo,
      LocalDateTime procDttm) {
    this.commGrpCdId = commGrpCdId;
    this.commGrpCd = commGrpCd;
    this.commGrpNm = commGrpNm;
    this.useFg = useFg;
    this.rmrk = rmrk;
    this.regUserNo = regUserNo;
    this.regDttm = regDttm;
    this.procUserNo = procUserNo;
    this.procDttm = procDttm;
  }

  public static GroupCodeListSearchResponseVO of(GroupCodeEntity groupCodeEntity) {
    return builder()
        .commGrpCdId(String.valueOf(groupCodeEntity.getId()))
        .commGrpCd(String.valueOf(groupCodeEntity.getCode()))
        .commGrpNm(groupCodeEntity.getName())
        .useFg(convertBoolean(groupCodeEntity.getIsUsed()))
        .rmrk(groupCodeEntity.getRemark())
        .regUserNo(groupCodeEntity.getCreatedBy())
        .regDttm(groupCodeEntity.getCreatedDate())
        .procUserNo(groupCodeEntity.getLastModifiedBy())
        .procDttm(groupCodeEntity.getLastModifiedDate())
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
