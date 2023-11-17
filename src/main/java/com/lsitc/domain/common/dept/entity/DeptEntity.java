package com.lsitc.domain.common.dept.entity;

import java.time.LocalDateTime;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.lsitc.global.auditing.Auditable;
import com.lsitc.global.common.BaseAbstractEntity;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class DeptEntity extends BaseAbstractEntity
    implements Auditable<Long, LocalDateTime> {

  private Long id;
  private String name;
  private Long parentsId;
  private String remark;

  @Builder
  private DeptEntity(Long id, String name, Long parentsId, String remark) {
    this.id = id;
    this.name = name;
    this.parentsId = parentsId;
    this.remark = remark;
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }

}
