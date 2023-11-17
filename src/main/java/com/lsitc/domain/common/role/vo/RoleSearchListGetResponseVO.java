package com.lsitc.domain.common.role.vo;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.lsitc.domain.common.role.entity.RoleEntity;
import lombok.Builder;
import lombok.Getter;

@Getter
public class RoleSearchListGetResponseVO {

  private final String roleId;
  private final String roleNm;
  private final String rmrk;
  private final String regUserNo;
  private final String regDttm;
  private final String procUserNo;
  private final String procDttm;

  @Builder
  private RoleSearchListGetResponseVO(String roleId, String roleNm, String rmrk, String regUserNo,
      String regDttm, String procUserNo, String procDttm) {
    this.roleId = roleId;
    this.roleNm = roleNm;
    this.rmrk = rmrk;
    this.regUserNo = regUserNo;
    this.regDttm = regDttm;
    this.procUserNo = procUserNo;
    this.procDttm = procDttm;
  }

  public static RoleSearchListGetResponseVO of(RoleEntity roleInfo) {
    return builder()
        .roleId(String.valueOf(roleInfo.getId()))
        .roleNm(roleInfo.getName())
        .rmrk(roleInfo.getRemark())
        .regUserNo(String.valueOf(roleInfo.getCreatedBy()))
        .regDttm(String.valueOf(roleInfo.getCreatedDate()))
        .procUserNo(String.valueOf(roleInfo.getLastModifiedBy()))
        .procDttm(String.valueOf(roleInfo.getLastModifiedDate()))
        .build();
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}
