package com.lsitc.domain.common.bloc.entity;

import com.lsitc.global.auditing.Auditable;
import com.lsitc.global.auditing.SoftDeletable;
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
public class BlocEntity extends BaseAbstractEntity implements Auditable<Long, LocalDateTime>,
    SoftDeletable<Long, LocalDateTime> {

  private Long id;
  private String name;
  private String remark;

  @Builder
  private BlocEntity(long id, String name, String remark) {
    this.id = id;
    this.name = name;
    this.remark = remark;
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}
