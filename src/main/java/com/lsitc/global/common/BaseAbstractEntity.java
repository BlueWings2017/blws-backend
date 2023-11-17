package com.lsitc.global.common;

import com.lsitc.global.auditing.SoftDeletable;
import java.time.LocalDateTime;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public abstract class BaseAbstractEntity {

  private Long createdBy;
  private LocalDateTime createdDate;
  private Long lastModifiedBy;
  private LocalDateTime lastModifiedDate;
  private boolean isDeleted;
  private Long deletedBy;
  private LocalDateTime deletedDate;

  public void delete() {
    if (this instanceof SoftDeletable) {
      setDeleted(true);
    }
  }
}
