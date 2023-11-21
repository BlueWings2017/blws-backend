package com.blws.global.auditing;

import java.time.temporal.TemporalAccessor;

public interface DateTimeProvider {

  TemporalAccessor getNow();
}
