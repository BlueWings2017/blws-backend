package com.blws.global.config;


import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.filter.CorsFilter;
import org.zalando.problem.spring.web.advice.security.SecurityProblemSupport;

import com.blws.global.jwt.JWTConfigurer;
import com.blws.global.jwt.JWTTokenProvider;

@RequiredArgsConstructor
@EnableWebSecurity
@Profile("dev")
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
@Import(SecurityProblemSupport.class)
public class DevSecurityConfig {

  private final JWTTokenProvider jWTTokenProvider;
  private final CorsFilter corsFilter;
  private final SecurityProblemSupport problemSupport;


  @Bean
  public WebSecurityCustomizer ignoringCustomizer() {
    return (web) -> web.ignoring().antMatchers(
            "/v3/api-docs","/swagger*/**","/common/auth/signin","/common/auth/signout");
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {

    httpSecurity
            .csrf().disable()
            .addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)
            .exceptionHandling()
            .authenticationEntryPoint(problemSupport)
            .accessDeniedHandler(problemSupport);

    httpSecurity
            .headers()
            .contentSecurityPolicy("default-src 'self'; frame-src 'self' data:; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:")
            .and()
            .referrerPolicy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
            .and()
            .frameOptions().sameOrigin();

    httpSecurity.sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

    httpSecurity.authorizeRequests()
            .antMatchers("/swagger-ui/**").permitAll() // swagger
            .antMatchers("/v3/api-docs").permitAll()
            .antMatchers("/common/auth/**").permitAll()
            .anyRequest().authenticated() // 나머지 경로는 jwt 인증 해야함
            .and()
            .httpBasic()
            .and()
            .apply(securityConfigurerAdapter());

    return httpSecurity.build();

  }

  private JWTConfigurer securityConfigurerAdapter() {
    return new JWTConfigurer(jWTTokenProvider);
  }

  @Bean
  public BCryptPasswordEncoder encoderPwd() {
    return new BCryptPasswordEncoder();
  }

}
