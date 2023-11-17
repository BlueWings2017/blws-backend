package com.lsitc.global.error.exception;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.lsitc.global.error.ResponseCode;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@JsonFormat(shape = JsonFormat.Shape.OBJECT)
public enum ErrorCode implements ResponseCode {
  // Common
  INVALID_INPUT_VALUE(HttpStatus.BAD_REQUEST.value(), "CM001", "Invalid Input Value"),
  METHOD_NOT_ALLOWED(HttpStatus.METHOD_NOT_ALLOWED.value(), "CM002", "Invalid Input Value"),
  INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR.value(), "CM003", "Server Error"),
  INVALID_TYPE_VALUE(HttpStatus.BAD_REQUEST.value(), "CM004", "Invalid Type Value"),
  HANDLE_ACCESS_DENIED(HttpStatus.FORBIDDEN.value(), "CM005", "Access is Denied"),
  PAYLOAD_TOO_LARGE(HttpStatus.PAYLOAD_TOO_LARGE.value(), "CM006", "Payload Too Large"),
  UNAUTHORIZED(HttpStatus.UNAUTHORIZED.value(), "CM007", "Unauthorized"),
  INVALID_ACCESS(HttpStatus.UNAUTHORIZED.value(), "CM007", "Invalid Access"),
  FORBIDDEN(HttpStatus.FORBIDDEN.value(), "CM008", "Forbidden");

  @Getter
  private final int status;
  @Getter
  private final String code;
  @Getter
  private final String message;

  ErrorCode(final int status, final String code, final String message) {
    this.status = status;
    this.message = message;
    this.code = code;
  }
}