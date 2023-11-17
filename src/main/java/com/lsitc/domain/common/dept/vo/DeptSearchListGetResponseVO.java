package com.lsitc.domain.common.dept.vo;

import java.time.LocalDateTime;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.lsitc.domain.common.dept.entity.DeptEntity;
import lombok.Builder;
import lombok.Getter;

@Getter
public class DeptSearchListGetResponseVO {

  private final Long id;
  private final String name;
  private final Long parentsId;
  private final String remark;
  private final Long createdBy;
  private final LocalDateTime createdDate;
  private final Long lastModifiedBy;
  private final LocalDateTime lastModifiedDate;

  @Builder
  private DeptSearchListGetResponseVO(Long id, String name, Long parentsId, String remark,
      Long createdBy, LocalDateTime createdDate, Long lastModifiedBy,
      LocalDateTime lastModifiedDate) {
    this.id = id;
    this.name = name;
    this.parentsId = parentsId;
    this.remark = remark;
    this.createdBy = createdBy;
    this.createdDate = createdDate;
    this.lastModifiedBy = lastModifiedBy;
    this.lastModifiedDate = lastModifiedDate;
  }

  public static DeptSearchListGetResponseVO of(DeptEntity deptInfo) {
    return builder().id(deptInfo.getId())
        .name(deptInfo.getName())
        .parentsId(deptInfo.getParentsId())
        .remark(deptInfo.getRemark())
        .createdBy(deptInfo.getCreatedBy())
        .createdDate(deptInfo.getCreatedDate())
        .lastModifiedBy(deptInfo.getLastModifiedBy())
        .lastModifiedDate(deptInfo.getLastModifiedDate())
        .build();
  }
  
  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }

}
