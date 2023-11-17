package com.lsitc.domain.common.role.exception;

import com.lsitc.global.error.exception.BusinessException;
import com.lsitc.global.error.exception.ErrorCode;

public class RoleException extends BusinessException {

  public RoleException(String message, ErrorCode errorCode) {
    super(message, errorCode);
  }

  public RoleException(String message) {
    super(message, ErrorCode.INTERNAL_SERVER_ERROR);
  }
  
  public RoleException(ErrorCode errorCode) {
    super(errorCode);
  }
}
