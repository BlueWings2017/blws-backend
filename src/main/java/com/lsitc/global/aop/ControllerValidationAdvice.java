package com.lsitc.global.aop;

import com.lsitc.global.validation.CollectionValidator;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.InitBinder;

@ControllerAdvice
public class ControllerValidationAdvice {

  @InitBinder
  public void initBinder(WebDataBinder binder) {
    binder.addValidators(new CollectionValidator());
  }
}