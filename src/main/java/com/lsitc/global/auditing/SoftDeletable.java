package com.lsitc.global.auditing;

import java.time.temporal.TemporalAccessor;
import com.fasterxml.jackson.annotation.JsonIgnore;

public interface SoftDeletable<U, T extends TemporalAccessor> {

  @JsonIgnore
  boolean isDeleted();

  @JsonIgnore
  U getDeletedBy();

  @JsonIgnore
  void setDeletedBy(U deletedBy);

  @JsonIgnore
  T getDeletedDate();

  @JsonIgnore
  void setDeletedDate(T deletedDate);

  @JsonIgnore
  void delete();
}
