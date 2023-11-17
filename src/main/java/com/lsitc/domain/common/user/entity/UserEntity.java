package com.lsitc.domain.common.user.entity;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Collections;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import com.lsitc.global.auditing.Auditable;
import com.lsitc.global.auditing.SoftDeletable;
import com.lsitc.global.common.BaseAbstractEntity;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class UserEntity extends BaseAbstractEntity
    implements UserDetails, Auditable<Long, LocalDateTime>, SoftDeletable<Long, LocalDateTime> {

  private static final long serialVersionUID = 7428290075155619330L;

  private Long id;
  private String userId;
  private String password;
  private String name;
  private String email;
  private String phoneNumber;
  private String accessToken;
  private String refreshToken;
  private Integer roleId;

  @Builder
  private UserEntity(Long id, String userId, String password, String name, String email,
      String phoneNumber,String accessToken, String refreshToken,Integer roleId) {
    this.id = id;
    this.userId = userId;
    this.password = password;
    this.name = name;
    this.email = email;
    this.phoneNumber = phoneNumber;
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    this.roleId = roleId;
  }

  public static UserEntity AnonymousUser() {
    return builder().id(0L).userId("anonymous").name("anonymous").roleId(1).build();
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {

    String roleId = this.roleId  == null ? "1" : this.roleId.toString();

    // FIXME 권한 관련 로직이 들어가는 곳
    return Collections.singletonList(new SimpleGrantedAuthority(roleId));
  }

  @Override
  public String getPassword() {
    return this.password;
  }

  @Override
  public String getUsername() {
    return this.userId;
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return !isDeleted();
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.JSON_STYLE);
  }
}
