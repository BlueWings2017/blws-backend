package com.blws.global.aop;

import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.InitBinder;

import com.blws.global.validation.CollectionValidator;

@ControllerAdvice
public class ControllerValidationAdvice {

  @InitBinder
  public void initBinder(WebDataBinder binder) {
    binder.addValidators(new CollectionValidator());
  }
}