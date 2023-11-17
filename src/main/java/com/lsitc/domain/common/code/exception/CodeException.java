package com.lsitc.domain.common.code.exception;

import com.lsitc.global.error.exception.BusinessException;
import com.lsitc.global.error.exception.ErrorCode;

public class CodeException extends BusinessException {

  public CodeException(String message, ErrorCode errorCode) {
    super(message, errorCode);
  }

  public CodeException(String message) {
    super(message, ErrorCode.INTERNAL_SERVER_ERROR);
  }

  public CodeException(ErrorCode errorCode) {
    super(errorCode);
  }
}
