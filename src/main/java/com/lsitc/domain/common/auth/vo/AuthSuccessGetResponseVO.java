package com.lsitc.domain.common.auth.vo;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.lsitc.domain.common.user.entity.UserEntity;
import lombok.Builder;
import lombok.Getter;

@Getter
public class AuthSuccessGetResponseVO {

  private final Long id;
  private final String userId;
  private final String name;
  private final String email;
  private final String phoneNumber;

  @Builder
  private AuthSuccessGetResponseVO(Long id, String userId, String name, String email,
      String phoneNumber) {
    this.id = id;
    this.userId = userId;
    this.name = name;
    this.email = email;
    this.phoneNumber = phoneNumber;
  }

  public static AuthSuccessGetResponseVO of(UserEntity userEntity) {
    return builder().id(userEntity.getId())
        .userId(userEntity.getUserId())
        .name(userEntity.getName())
        .email(userEntity.getEmail())
        .phoneNumber(userEntity.getPhoneNumber())
        .build();
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}
