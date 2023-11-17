package com.lsitc.domain.common.code.entity;

import com.lsitc.global.auditing.Auditable;
import com.lsitc.global.common.BaseAbstractEntity;
import java.time.LocalDateTime;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class GroupCodeEntity extends BaseAbstractEntity implements Auditable<Long, LocalDateTime> {

  private Long id;
  private String code;
  private String name;
  private Boolean isUsed;
  private String remark;

  @Builder
  private GroupCodeEntity(Long id, String code, String name, Boolean isUsed, String remark) {
    this.id = id;
    this.code = code;
    this.name = name;
    this.isUsed = isUsed;
    this.remark = remark;
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}
