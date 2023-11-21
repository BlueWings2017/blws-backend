package com.blws.domain.common.user.vo;

import javax.validation.constraints.PositiveOrZero;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.blws.domain.common.user.entity.UserEntity;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class UserModifyRequestVO {

  private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

  @PositiveOrZero(message = "음수의 ID는 사용할 수 없습니다.")
  private final Long id;
  private final String userId;
  private final String password;
  private final String name;
  private final String email;
  private final String phoneNumber;
  private int roleId;

  public UserEntity toEntity() {
    return UserEntity.builder()
            .id(id)
            .userId(userId)
            .password(password != null ? passwordEncoder.encode(password) : null)
            .name(name)
            .email(email)
            .phoneNumber(phoneNumber)
            .roleId(roleId)
            .build();
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}
