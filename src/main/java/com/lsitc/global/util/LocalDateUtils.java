package com.lsitc.global.util;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

public class LocalDateUtils {
  
  public static LocalDate parse(String str, String pattern) {
    return LocalDate.parse(str, DateTimeFormatter.ofPattern(pattern));
  }
  
  public static LocalDate parseYyyymmdd(String str) {
    return parse(str, "yyyyMMdd");
  }
  
  public static LocalDate getFirstDayOfMonth(LocalDate date) {
    return LocalDate.of(date.getYear(), date.getMonth(), 1);
  }
  
  public static LocalDate getLastDayOfMonth(LocalDate date) {
    return LocalDate.of(date.getYear(), date.getMonth(), date.lengthOfMonth());
  }
}
