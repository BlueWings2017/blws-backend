package com.lsitc.domain.common.user.vo;

import javax.validation.constraints.NotBlank;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.lsitc.domain.common.user.entity.UserEntity;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class UserAddRequestVO {

  private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

  @NotBlank(message = "userId에 빈값이 들어왔습니다.")
  private final String userId;
  @NotBlank(message = "password에 빈값이 들어왔습니다.")
  private final String password;
  private final String name;
  private final String email;
  private final String phoneNumber;
  private final Integer roleId;

  public UserEntity toEntity() {
    return UserEntity.builder()
        .userId(userId)
        .password(passwordEncoder.encode(password))
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
