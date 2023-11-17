package com.lsitc.domain.sample.entity;

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
public class SampleEntity extends BaseAbstractEntity implements Auditable<Long, LocalDateTime>,
    SoftDeletable<Long, LocalDateTime> {

  private Long id;
  private String foo;
  private String bar;
  private String comment;

  @Builder
  private SampleEntity(long id, String foo, String bar, String comment) {
    this.id = id;
    this.foo = foo;
    this.bar = bar;
    this.comment = comment;
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}