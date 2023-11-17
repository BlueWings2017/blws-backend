package com.lsitc.domain.common.calendar.service;

import java.time.DayOfWeek;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.lsitc.domain.common.calendar.dao.CalendarDAO;
import com.lsitc.domain.common.calendar.entity.CalendarEntity;
import com.lsitc.domain.common.calendar.vo.CalendarModifyRequestVO;
import com.lsitc.domain.common.calendar.vo.CalendarModifyResponseVO;
import com.lsitc.domain.common.calendar.vo.CalendarSearchListGetRequestVO;
import com.lsitc.domain.common.calendar.vo.CalendarSearchListGetResponseVO;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@AllArgsConstructor
public class CalendarService {

  private final CalendarDAO calendarDAO;

  @Transactional
  public List<CalendarSearchListGetResponseVO> searchCalendarList(
      final CalendarSearchListGetRequestVO calendarSearchListGetRequestVO) {
    CalendarEntity calendarEntity = calendarSearchListGetRequestVO.toEntity();
    log.info(calendarEntity.toString());

    List<CalendarEntity> calendarEntityList =
        calendarDAO.selectCalendarByConditions(calendarEntity);

    if (calendarEntityList.size() < 1) {
      calendarEntityList = createCalendar(calendarEntity);
    }

    log.info(calendarEntityList.toString());

    return calendarEntityList.stream().map(CalendarSearchListGetResponseVO::of)
        .collect(Collectors.toList());
  }

  private List<CalendarEntity> createCalendar(CalendarEntity calendarEntity) {
    List<CalendarEntity> holidayList = calendarDAO.selectHolidayByConditions(calendarEntity);
    List<CalendarEntity> calendarList = new ArrayList<CalendarEntity>();

    for (int i = 0; i < calendarEntity.getStartDate().lengthOfMonth(); i++) {
      LocalDate date = calendarEntity.getStartDate().plusDays(i);
      DayOfWeek dayOfWeek = date.getDayOfWeek();
      
      boolean isHoliday = dayOfWeek.getValue() == 7;
      String holidayName =
          dayOfWeek.getValue() == 6 ? "토요일" : dayOfWeek.getValue() == 7 ? "일요일" : null;
      String remark = null;

      CalendarEntity holiday = holidayList.stream().filter(entity -> date.isEqual(entity.getDate()))
          .findFirst().orElse(null);

      if (holiday != null) {
        isHoliday = holiday.isHoliday();
        holidayName = holiday.getHolidayName();
        remark = holiday.getRemark();
      }

      CalendarEntity entity = CalendarEntity.builder().date(date).isHoliday(isHoliday)
          .holidayName(holidayName).remark(remark).build();

      calendarList.add(entity);
    }

    calendarDAO.insertCalendarList(calendarList);

    return calendarDAO.selectCalendarByConditions(calendarEntity);
  }

  @Transactional
  public CalendarModifyResponseVO modifyCalendar(
      List<CalendarModifyRequestVO> calendarModifyRequestVO) {
    List<CalendarEntity> calendarEntityList = calendarModifyRequestVO.stream()
        .map(CalendarModifyRequestVO::toEntity).collect(Collectors.toList());

    int updateRows = calendarDAO.updateCalendarByDate(calendarEntityList);

    log.info(calendarEntityList.toString());
    return CalendarModifyResponseVO.of(updateRows);
  }

}
