package com.lsitc.global.auditing;

import java.time.LocalDateTime;
import java.time.temporal.TemporalAccessor;

public enum CurrentDateTimeProvider implements DateTimeProvider {
  INSTANCE;

  public TemporalAccessor getNow() {
    return LocalDateTime.now();
  }
}
