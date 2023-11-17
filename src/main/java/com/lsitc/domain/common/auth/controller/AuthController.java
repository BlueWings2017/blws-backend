package com.lsitc.domain.common.auth.controller;

import com.lsitc.domain.common.auth.vo.AuthFailureGetRequestVO;
import com.lsitc.domain.common.auth.vo.AuthSuccessGetResponseVO;
import com.lsitc.global.jwt.JWTTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.io.IOException;

@Slf4j
@RequestMapping("/common/auth")
@RestController
@RequiredArgsConstructor
public class AuthController {

  private final JWTTokenProvider jWTTokenProvider;

  @PostMapping("/signin")
  public AuthSuccessGetResponseVO authorize(@Valid @RequestBody AuthFailureGetRequestVO loginVM,HttpServletResponse httpServletResponse) {
    return jWTTokenProvider.signIn(loginVM,httpServletResponse);
  }

  @GetMapping("/signout")
  public ResponseEntity<Void> logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException {
      jWTTokenProvider.signOut(httpServletRequest,httpServletResponse);
    return ResponseEntity.ok().build();
  }

}
