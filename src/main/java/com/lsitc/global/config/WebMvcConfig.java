package com.lsitc.global.config;

import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateSerializer;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateTimeSerializer;
import com.lsitc.global.interceptor.ControllerLoggingInterceptor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.util.CollectionUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.time.format.DateTimeFormatter;
import java.util.Calendar;

@Configuration
@RequiredArgsConstructor
public class WebMvcConfig implements WebMvcConfigurer {
    //날짜포멧
    private static final String DATE_FORMAT = "yyyy-MM-dd";
    //날짜시간포멧
    private static final String DATE_TIME_FORMAT = "yyyy-MM-dd HH:mm:ss";

    private final ApplicationProperties applicationProperties;

//    @Autowired
//    private LoginChkInterceptor loginchkInterceptor;
//
//    @Autowired
//    private AuthChkInterceptor authChkInterceptor;

    @Autowired
    private ControllerLoggingInterceptor controllerLoggingInterceptor;

    /**
     * @methodName  : addInterceptors
     * @date        : 2021.02.19
     * @desc        : 인터셉터를 추가한다.
     * @param registry
     */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // 로깅 인터셉터
        registry.addInterceptor(controllerLoggingInterceptor)
                .excludePathPatterns("/common/auth/**").excludePathPatterns("/swagger-*/**").excludePathPatterns("/v3/api-docs")
                .excludePathPatterns("/logout**").excludePathPatterns("/css/**").excludePathPatterns("/images/**")
                .excludePathPatterns("/js/**").excludePathPatterns("/plugins/**").excludePathPatterns("/dist/**")
                .excludePathPatterns("/bootstrap/**").excludePathPatterns("/error/**")
                .excludePathPatterns("/favicon.ico")
                .addPathPatterns("/**");
    }

    /**
     * @methodName  : addCorsMappings
     * @date        : 2021.02.19
     * @desc        : 
     * @param registry
     */
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedMethods(
                        HttpMethod.GET.name(),
                        HttpMethod.POST.name(),
                        HttpMethod.PUT.name(),
                        HttpMethod.DELETE.name());
    }

    /**
     * @methodName  : jackson2ObjectMapperBuilderCustomizer
     * @date        : 2021.02.19
     * @desc        : controller에서 request를 변환 시 날짜포멧을 지정해주기 위해 설정을 추가한다. 
     * @return
     */
    @Bean
    public Jackson2ObjectMapperBuilderCustomizer jackson2ObjectMapperBuilderCustomizer() {
        return jacksonObjectMapperBuilder -> {
            //JacksonObjectMapper에 날짜 포멧 지정.
            jacksonObjectMapperBuilder.timeZone( Calendar.getInstance().getTimeZone());
            jacksonObjectMapperBuilder.simpleDateFormat(DATE_TIME_FORMAT);
            jacksonObjectMapperBuilder.serializers(new LocalDateSerializer(DateTimeFormatter.ofPattern(DATE_FORMAT)));
            jacksonObjectMapperBuilder.serializers(new LocalDateTimeSerializer(DateTimeFormatter.ofPattern(DATE_TIME_FORMAT)));
        };
    }

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = applicationProperties.getCors();
        if (!CollectionUtils.isEmpty(config.getAllowedOrigins()) || !CollectionUtils.isEmpty(config.getAllowedOriginPatterns())) {
            source.registerCorsConfiguration("/api/**", config);
            source.registerCorsConfiguration("/management/**", config);
            source.registerCorsConfiguration("/v3/api-docs", config);
            source.registerCorsConfiguration("/swagger-ui/**", config);
            source.registerCorsConfiguration("/common/auth/**", config);

        }
        return new CorsFilter(source);
    }

}