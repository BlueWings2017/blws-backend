package com.lsitc.domain.common.user.service;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.lsitc.domain.common.user.dao.UserDAO;
import com.lsitc.domain.common.user.entity.UserEntity;
import com.lsitc.domain.common.user.exception.UserException;
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
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@AllArgsConstructor
public class UserService implements UserDetailsService {

  private final UserDAO userDAO;

  public UserInfoGetResponseVO getUserInfo(final UserInfoGetRequestVO userInfoGetRequestVO) {
    UserEntity userEntity = userInfoGetRequestVO.toEntity();
    log.info(userEntity.toString());
    
    UserEntity userInfo = null;
    
    if (userEntity.getId() != null) {
      userInfo = userDAO.selectUserById(userEntity);
    }
    if (userInfo == null && userEntity.getUserId() != null) {
      userInfo = userDAO.selectUserByUserId(userEntity);
    }

    return userInfo != null ? UserInfoGetResponseVO.of(userInfo)
        : UserInfoGetResponseVO.builder().build();
  }

  public List<UserListGetResponseVO> getUserList() {
    List<UserEntity> userEntityList = userDAO.selectAll();
    return userEntityList.stream().map(UserListGetResponseVO::of).collect(Collectors.toList());
  }

  public List<UserSearchListGetResponseVO> searchUserList(
      final UserSearchListGetRequestVO userSearchListGetRequestVO) {
    UserEntity userEntity = userSearchListGetRequestVO.toEntity();
    List<UserEntity> userEntityList = userDAO.selectUserByConditions(userEntity);
    return userEntityList.stream().map(UserSearchListGetResponseVO::of)
        .collect(Collectors.toList());
  }

  @Transactional
  public UserAddResponseVO addUser(final List<UserAddRequestVO> userAddRequestVO) {
    List<UserEntity> userEntityList =
        userAddRequestVO.stream().map(UserAddRequestVO::toEntity).collect(Collectors.toList());
    log.info(userEntityList.toString());
    int addRows = userDAO.insertUserList(userEntityList);
    return UserAddResponseVO.of(addRows);
  }

  @Transactional
  public UserModifyResponseVO modifyUser(final List<UserModifyRequestVO> userModifyRequestVO) {
    List<UserEntity> userEntityList = userModifyRequestVO.stream()
        .map(UserModifyRequestVO::toEntity).collect(Collectors.toList());

    List<UserEntity> updateList = new ArrayList<>();
    List<UserEntity> insertList = new ArrayList<>();

    userEntityList.forEach(userEntity -> {
      if (isUpdate(userEntity)) {
        updateList.add(userEntity);
      } else {
        insertList.add(userEntity);
      }
    });

    int upsertRows = (updateList.size() > 0 ? userDAO.updateUserById(updateList) : 0)
        + (insertList.size() > 0 ? userDAO.insertUserWithId(insertList) : 0);

    log.info(userEntityList.toString());
    return UserModifyResponseVO.of(upsertRows);
  }

  private boolean isUpdate(UserEntity targetEntity) {
    UserEntity userEntity = userDAO.selectUserById(targetEntity);
    return userEntity != null;
  }

  @Transactional
  public UserRemoveResponseVO removeUser(final List<UserRemoveRequestVO> userRemoveRequestVO)
      throws UserException {
    List<UserEntity> userEntityList = userRemoveRequestVO.stream()
        .map(UserRemoveRequestVO::toEntity).collect(Collectors.toList());
    log.info(userEntityList.toString());
    int deleteRows = softDeleteUser(userEntityList);
    return UserRemoveResponseVO.of(deleteRows);
  }
  
  private int softDeleteUser(List<UserEntity> targetEntityList) {
    List<UserEntity> userEntityList = userDAO.selectUserByIds(targetEntityList);
    if (userEntityList.isEmpty()) {
      throw new UserException("userEntity is not exist");
    }
    userEntityList.forEach(UserEntity::delete);
    log.info(userEntityList.toString());
    return userDAO.updateUserIsDeletedById(userEntityList);
  }
  
  @Override
  public UserDetails loadUserByUsername(String userId) throws UsernameNotFoundException {
    UserEntity userEntity = UserEntity.builder().userId(userId).build();
    UserEntity resultEntity = userDAO.selectUserByUserId(userEntity);

    if (resultEntity == null) {
      throw new UsernameNotFoundException(userId);
    }

    return resultEntity;
  }

  public int updateUserToken(UserEntity userEntity){
    return userDAO.updateUserToken(userEntity);
  }

}
