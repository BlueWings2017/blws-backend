package com.lsitc.global.error;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class ErrorResponse {

  private int status;
  private String code;
  private String message;

  private ErrorResponse(final ResponseCode code, final String message) {
    this.status = code.getStatus();
    this.code = code.getCode();
    this.message = message;
  }

  private ErrorResponse(final ResponseCode code) {
    this(code, code.getMessage());
  }

  public static ErrorResponse of(final ResponseCode code) {
    return new ErrorResponse(code);
  }
}
