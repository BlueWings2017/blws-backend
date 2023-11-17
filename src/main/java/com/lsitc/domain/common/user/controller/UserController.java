package com.lsitc.domain.common.user.controller;

import java.util.List;
import javax.validation.Valid;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.lsitc.domain.common.user.exception.UserException;
import com.lsitc.domain.common.user.service.UserService;
import com.lsitc.domain.common.user.vo.UserAddRequestVO;
import com.lsitc.domain.common.user.vo.UserAddResponseVO;
import com.lsitc.domain.common.user.vo.UserInfoGetRequestVO;
import com.lsitc.domain.common.user.vo.UserInfoGetResponseVO;
import com.lsitc.domain.common.user.vo.UserListGetResponseVO;
import com.lsitc.domain.common.user.vo.UserModifyRequestVO;
import com.lsitc.domain.common.user.vo.UserModifyResponseVO;
import com.lsitc.domain.common.user.vo.UserRemoveRequestVO;
import com.lsitc.domain.common.user.vo.UserRemoveResponseVO;
import com.lsitc.domain.common.user.vo.UserSearchListGetRequestVO;
import com.lsitc.domain.common.user.vo.UserSearchListGetResponseVO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequestMapping("/common/user")
@RestController
@RequiredArgsConstructor
public class UserController {

  private final UserService userService;

  @GetMapping("/info")
  public UserInfoGetResponseVO getUserInfo(@Valid final UserInfoGetRequestVO userInfoGetRequestVO)
      throws UserException {
    log.info(userInfoGetRequestVO.toString());
    UserInfoGetResponseVO userInfoGetResponseVO = userService.getUserInfo(userInfoGetRequestVO);
    log.info(userInfoGetResponseVO.toString());
    return userInfoGetResponseVO;
  }

  @GetMapping("/myinfo")
  public UserInfoGetResponseVO getMyInfo()throws UserException {
    String userId = SecurityContextHolder.getContext().getAuthentication().getName();
    UserInfoGetResponseVO userInfoGetResponseVO = userService.getUserInfo(UserInfoGetRequestVO.builder().userId(userId).build());
    log.info(userInfoGetResponseVO.toString());
    return userInfoGetResponseVO;
  }

  @GetMapping("/list")
  public List<UserListGetResponseVO> getUserList() throws UserException {
    List<UserListGetResponseVO> userListGetResponseVOList = userService.getUserList();
    log.info(userListGetResponseVOList.toString());
    return userListGetResponseVOList;
  }

  @GetMapping("/search")
  public List<UserSearchListGetResponseVO> searchUserList(
      @Valid final UserSearchListGetRequestVO userSearchListGetRequestVO) throws UserException {
    List<UserSearchListGetResponseVO> userListGetResponseVOList =
        userService.searchUserList(userSearchListGetRequestVO);
    log.info(userListGetResponseVOList.toString());
    return userListGetResponseVOList;
  }

  @PostMapping
  public UserAddResponseVO addUser(
      @RequestBody @Valid final List<UserAddRequestVO> userAddRequestVO) throws UserException {
    log.info(userAddRequestVO.toString());
    UserAddResponseVO userAddResponseVO = userService.addUser(userAddRequestVO);
    log.info(userAddResponseVO.toString());
    return userAddResponseVO;
  }

  @PutMapping
  public UserModifyResponseVO modifyUser(
      @RequestBody @Valid final List<UserModifyRequestVO> userModifyRequestVO)
      throws UserException {
    log.info(userModifyRequestVO.toString());
    UserModifyResponseVO userModifyResponseVO = userService.modifyUser(userModifyRequestVO);
    log.info(userModifyResponseVO.toString());
    return userModifyResponseVO;
  }

  @DeleteMapping
  public UserRemoveResponseVO removeUser(
      @RequestBody @Valid final List<UserRemoveRequestVO> userRemoveRequestVO)
      throws UserException {
    log.info(userRemoveRequestVO.toString());
    UserRemoveResponseVO userRemoveResponseVO = userService.removeUser(userRemoveRequestVO);
    log.info(userRemoveResponseVO.toString());
    return userRemoveResponseVO;
  }
}
