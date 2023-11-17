package com.lsitc.global.auditing;

import java.time.temporal.TemporalAccessor;
import com.fasterxml.jackson.annotation.JsonIgnore;

public interface Auditable<U, T extends TemporalAccessor> {
  @JsonIgnore
  U getCreatedBy();
  
  @JsonIgnore
  void setCreatedBy(U createdBy);

  @JsonIgnore
  T getCreatedDate();

  @JsonIgnore
  void setCreatedDate(T creationDate);

  @JsonIgnore
  U getLastModifiedBy();

  @JsonIgnore
  void setLastModifiedBy(U lastModifiedBy);

  @JsonIgnore
  T getLastModifiedDate();

  @JsonIgnore
  void setLastModifiedDate(T lastModifiedDate);
}
