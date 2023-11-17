package com.lsitc.domain.common.user.vo;

import java.time.LocalDateTime;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import com.lsitc.domain.common.user.entity.UserEntity;
import lombok.Builder;
import lombok.Getter;

@Getter
public class UserSearchListGetResponseVO {

  private final Long id;
  private final String userId;
  private final String name;
  private final String email;
  private final String phoneNumber;
  private final Long createdBy;
  private final LocalDateTime createdDate;
  private final Long lastModifiedBy;
  private final LocalDateTime lastModifiedDate;
  private final Integer roleId;

  @Builder
  private UserSearchListGetResponseVO(Long id, String userId, String name, String email,
      String phoneNumber, Long createdBy, LocalDateTime createdDate, Long lastModifiedBy,
      LocalDateTime lastModifiedDate, int roleId) {
    this.id = id;
    this.userId = userId;
    this.name = name;
    this.email = email;
    this.phoneNumber = phoneNumber;
    this.createdBy = createdBy;
    this.createdDate = createdDate;
    this.lastModifiedBy = lastModifiedBy;
    this.lastModifiedDate = lastModifiedDate;
    this.roleId = roleId;
  }

  public static UserSearchListGetResponseVO of(UserEntity resultEntity) {
    return builder().id(resultEntity.getId())
        .userId(resultEntity.getUserId())
        .name(resultEntity.getName())
        .email(resultEntity.getEmail())
        .phoneNumber(resultEntity.getPhoneNumber())
        .createdBy(resultEntity.getCreatedBy())
        .createdDate(resultEntity.getCreatedDate())
        .lastModifiedBy(resultEntity.getLastModifiedBy())
        .lastModifiedDate(resultEntity.getLastModifiedDate())
        .roleId(resultEntity.getRoleId())
        .build();
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}
