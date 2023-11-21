/*
 * 상기 프로그램에 대한 저작권을 포함한 지적재산권은 LS ITC에 있으며,
 * LS ITC가 명시적으로 허용하지 않은 사용, 복사, 변경, 제3자에의 공개, 배포는 엄격히 금지되며,
 * LS ITC의 지적재산권 침해에 해당됩니다.
 * (Copyright ⓒ 2021 LS ITC. All Rights Reserved| Confidential)
 *
 * You are strictly prohibited to copy, disclose, distribute, modify, or use
 * this program in part or as a whole without the prior written consent of
 * LS ITC Business unit. LS ITC Business unit., owns the intellectual property rights in
 * and to this program.
 * (Copyright ⓒ 2021 LS ITC Business unit. All Rights Reserved| Confidential)
 * Author    : LS ITC
 * Created   : 2021-04-23 17:58:11
 */

package com.blws.domain;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

import com.blws.global.config.ApplicationProperties;

@SpringBootApplication(scanBasePackages = {"com.blws.global", "com.blws.domain"})
@EnableScheduling
@EnableConfigurationProperties({ ApplicationProperties.class })
public class Application {

    public static void main(String[] args) {

        SpringApplication.run(Application.class, args);
    }

}	
