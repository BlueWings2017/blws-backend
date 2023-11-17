package com.lsitc.global.auditing;

import com.lsitc.domain.common.user.entity.UserEntity;
import org.springframework.security.core.context.SecurityContextHolder;

public enum CurrentUserEntityProvider implements UserProvider<UserEntity, Long> {
  INSTANCE;

  @Override
  public UserEntity getUser() {

    Object principal =null;

    try {
      principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }catch (Exception e){
      e.printStackTrace();
    }

    if (principal instanceof UserEntity) {
      return (UserEntity) principal;
    } else {
      return UserEntity.AnonymousUser();
    }

  }

  @Override
  public Long getId() {
    Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    if (principal instanceof UserEntity) {
      UserEntity userEntity = (UserEntity) principal;
      return userEntity.getId();
    } else {
      return UserEntity.AnonymousUser().getId();
    }
  }
}
