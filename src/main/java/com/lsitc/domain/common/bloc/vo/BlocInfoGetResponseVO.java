package com.lsitc.domain.common.bloc.vo;

import java.time.LocalDateTime;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.lsitc.domain.common.bloc.entity.BlocEntity;
import lombok.Builder;
import lombok.Getter;

@Getter
public class BlocInfoGetResponseVO {

  private final Long id;
  private final String name;
  private final boolean isDeleted;
  private final String remark;
  private final Long createdBy;
  private final LocalDateTime createdDate;
  private final Long lastModifiedBy;
  private final LocalDateTime lastModifiedDate;

  @Builder
  private BlocInfoGetResponseVO(long id, String name, boolean isDeleted, String remark,
      Long createdBy, LocalDateTime createdDate, Long lastModifiedBy,
      LocalDateTime lastModifiedDate) {
    this.id = id;
    this.name = name;
    this.isDeleted = isDeleted;
    this.remark = remark;
    this.createdBy = createdBy;
    this.createdDate = createdDate;
    this.lastModifiedBy = lastModifiedBy;
    this.lastModifiedDate = lastModifiedDate;
  }

  public static BlocInfoGetResponseVO of(BlocEntity blocInfo) {
    return builder().id(blocInfo.getId())
        .name(blocInfo.getName())
        .isDeleted(blocInfo.isDeleted())
        .remark(blocInfo.getRemark())
        .createdBy(blocInfo.getCreatedBy())
        .createdDate(blocInfo.getCreatedDate())
        .lastModifiedBy(blocInfo.getLastModifiedBy())
        .lastModifiedDate(blocInfo.getLastModifiedDate())
        .build();
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}
