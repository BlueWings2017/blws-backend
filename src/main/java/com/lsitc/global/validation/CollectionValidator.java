package com.lsitc.global.validation;

import java.util.Collection;
import javax.validation.Validation;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;
import org.springframework.validation.beanvalidation.SpringValidatorAdapter;

@Component
public class CollectionValidator implements Validator {

  private final Validator validator;

  public CollectionValidator() {
    this.validator = new SpringValidatorAdapter(
        Validation.buildDefaultValidatorFactory().getValidator()
    );
  }

  @Override
  public boolean supports(Class<?> clazz) {
    return true;
  }

  @Override
  public void validate(Object target, Errors errors) {
    if (target instanceof Collection) {
      for (Object object : (Collection) target) {
        validate(object, errors);
      }
    } else {
      validator.validate(target, errors);
    }
  }
}