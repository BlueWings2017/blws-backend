package com.lsitc.global.common;

import com.lsitc.global.auditing.SoftDeletable;
import java.time.LocalDateTime;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public abstract class BaseAbstractEntity {

  private String createdBy;
  private LocalDateTime createdDate;
  private String lastModifiedBy;
  private LocalDateTime lastModifiedDate;
  private int isDeleted;
  private String deletedBy;
  private LocalDateTime deletedDate;

  public void delete() {
    if (this instanceof SoftDeletable) {
      setIsDeleted(1);
    }
  }
}
