package com.lsitc.domain.common.user.exception;

import com.lsitc.global.error.exception.BusinessException;
import com.lsitc.global.error.exception.ErrorCode;

public class UserException extends BusinessException {

  public UserException(String message, ErrorCode errorCode) {
    super(message, errorCode);
  }

  public UserException(String message) {
    super(message, ErrorCode.INTERNAL_SERVER_ERROR);
  }
  
  public UserException(ErrorCode errorCode) {
    super(errorCode);
  }
}