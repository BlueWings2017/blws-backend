package com.lsitc.domain.common.calendar.dao;

import java.util.List;
import org.apache.ibatis.annotations.Mapper;
import com.lsitc.domain.common.calendar.entity.CalendarEntity;

@Mapper
public interface CalendarDAO {
  
  List<CalendarEntity> selectCalendarByConditions(CalendarEntity calendarEntity);

  List<CalendarEntity> selectHolidayByConditions(CalendarEntity calendarEntity);

  int insertCalendarList(List<CalendarEntity> calendarEntityList);

  int updateCalendarByDate(List<CalendarEntity> calendarEntityList);

}
