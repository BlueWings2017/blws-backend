package com.lsitc.domain.common.menu.exception;

import com.lsitc.global.error.exception.BusinessException;
import com.lsitc.global.error.exception.ErrorCode;

public class MenuException extends BusinessException {

  public MenuException(String message, ErrorCode errorCode) {
    super(message, errorCode);
  }

  public MenuException(String message) {
    super(message, ErrorCode.INTERNAL_SERVER_ERROR);
  }

  public MenuException(ErrorCode errorCode) {
    super(errorCode);
  }
}