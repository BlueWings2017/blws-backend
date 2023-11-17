package com.lsitc.domain.common.bloc.exception;

import com.lsitc.global.error.exception.BusinessException;
import com.lsitc.global.error.exception.ErrorCode;

public class BlocException extends BusinessException {

  public BlocException(String message, ErrorCode errorCode) {
    super(message, errorCode);
  }

  public BlocException(String message) {
    super(message, ErrorCode.INTERNAL_SERVER_ERROR);
  }

  public BlocException(ErrorCode errorCode) {
    super(errorCode);
  }
}
