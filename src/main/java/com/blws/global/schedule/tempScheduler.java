package com.blws.global.schedule;


import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Slf4j
@Component
public class tempScheduler {
    @Scheduled(cron = "0 0/10 * * * ?")
    public void testPrintRepeat() {
        DateTimeFormatter dtf =  DateTimeFormatter.ofPattern("yyyy-MM-dd hh:mm:ss");
        log.info("스케쥴러 테스트 " + LocalDateTime.now().format(dtf));
    }

}
