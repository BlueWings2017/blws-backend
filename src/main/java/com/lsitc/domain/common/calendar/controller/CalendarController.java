package com.lsitc.domain.common.calendar.controller;

import java.util.List;
import javax.validation.Valid;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.lsitc.domain.common.calendar.exception.CalendarException;
import com.lsitc.domain.common.calendar.service.CalendarService;
import com.lsitc.domain.common.calendar.vo.CalendarModifyRequestVO;
import com.lsitc.domain.common.calendar.vo.CalendarModifyResponseVO;
import com.lsitc.domain.common.calendar.vo.CalendarSearchListGetRequestVO;
import com.lsitc.domain.common.calendar.vo.CalendarSearchListGetResponseVO;
import com.lsitc.domain.common.user.exception.UserException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequestMapping("/common/calendar")
@RestController
@RequiredArgsConstructor
public class CalendarController {

  private final CalendarService calendarService;

  @GetMapping("/search")
  public List<CalendarSearchListGetResponseVO> searchCalendarList(
      @Valid final CalendarSearchListGetRequestVO calendarSearchListGetRequestVO)
      throws CalendarException {
    log.info(calendarSearchListGetRequestVO.toString());
    List<CalendarSearchListGetResponseVO> calendarSearchListGetResponseVO =
        calendarService.searchCalendarList(calendarSearchListGetRequestVO);
    log.info(calendarSearchListGetResponseVO.toString());
    return calendarSearchListGetResponseVO;
  }

  @PutMapping
  public CalendarModifyResponseVO modifyCalendar(
      @RequestBody @Valid final List<CalendarModifyRequestVO> calendarModifyRequestVO)
      throws UserException {
    log.info(calendarModifyRequestVO.toString());
    CalendarModifyResponseVO calendarModifyResponseVO =
        calendarService.modifyCalendar(calendarModifyRequestVO);
    log.info(calendarModifyResponseVO.toString());
    return calendarModifyResponseVO;
  }
}
